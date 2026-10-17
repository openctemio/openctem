package mcpoauth

// Access requests: a member whose consent is blocked because the
// organization admits only verified applications asks an administrator to
// approve the application's publisher; approving adds the publisher host to
// the organization's policy (docs/architecture/mcp-authorization.md,
// "Access requests").
//
// Threat model: the member supplies nothing but the id of an authorization
// request they claimed, so a request cannot name an arbitrary host or spoof
// an application name; every read and write is scoped to the session's
// tenant; approving loosens the policy and needs settings:write plus a
// recent sign-in (route); new requests are capped per member and per
// organization; administrators are notified once per new request, never
// per repeat.

import (
	"context"
	"fmt"
	"slices"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Access request limits.
const (
	// MaxAccessRequestsPerMemberPerDay is how many new requests one member
	// may open in an organization in 24 hours (repeats of a pending request
	// do not count).
	MaxAccessRequestsPerMemberPerDay = 5
	// MaxPendingAccessRequests is how many requests an organization may
	// have waiting at once.
	MaxPendingAccessRequests = 50
)

// PolicyWriter adds a publisher host to the organization's MCP policy and
// audits the change (*tenant.TenantService).
type PolicyWriter interface {
	AllowMCPClientHost(ctx context.Context, tenantID, host string, actx auditapp.AuditContext) error
}

// InAppNotifier delivers an in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

var (
	// ErrAccessRequestNotPossible: the application is not blocked for a
	// reason an approval can fix (MCP off, already allowed, or no publisher
	// host to approve).
	ErrAccessRequestNotPossible = fmt.Errorf("%w: this application cannot be requested", shared.ErrValidation)
	// ErrAccessRequestLimit: too many requests.
	ErrAccessRequestLimit = fmt.Errorf("%w: too many access requests", shared.ErrForbidden)
	// ErrAccessRequestsUnavailable: the server runs without the store.
	ErrAccessRequestsUnavailable = fmt.Errorf("%w: access requests are not available", shared.ErrNotImplemented)
)

// requestablePublisher is the host a member may ask the organization to
// approve for the request's client: only a metadata-document client blocked
// because it is not verified, with a host the policy accepts.
func (s *Service) requestablePublisher(p tenantdom.MCPSettings, c mcpoauth.Client, tenantID shared.ID) (string, bool) {
	if s.blockedReason(p, c, tenantID) != BlockedClientNotFound || c.Kind != mcpoauth.ClientKindMetadataDocument {
		return "", false
	}
	host := clientHost(c)
	check := tenantdom.MCPSettings{ClientHosts: []string{host}}
	if host == "" || check.Validate() != nil {
		return "", false
	}
	return host, true
}

// RequestAccess records the member's request to approve the publisher of
// the application behind authorization request requestID, which the member
// claimed in the consent page.
func (s *Service) RequestAccess(ctx context.Context, requestID, userID, tenantID shared.ID, actor Actor) (*mcpoauth.AccessRequest, error) {
	if s.accessRequests == nil {
		return nil, ErrAccessRequestsUnavailable
	}
	now := s.now()
	req, err := s.repo.ClaimRequest(ctx, requestID, userID, now)
	if err != nil || req.Client.BlockedAt != nil {
		return nil, ErrConsentUnavailable
	}
	if ok, err := s.members.IsActiveMember(ctx, tenantID, userID); err != nil || !ok {
		return nil, ErrConsentUnavailable
	}
	pol, err := s.policy(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read mcp policy: %w", err)
	}
	host, ok := s.requestablePublisher(pol, req.Client, tenantID)
	if !ok {
		return nil, ErrAccessRequestNotPossible
	}
	if _, err := s.accessRequests.PendingAccessRequestForHost(ctx, tenantID, host); err != nil {
		// A new request: within the member's and the organization's caps.
		n, err := s.accessRequests.CountAccessRequestsCreatedBy(ctx, tenantID, userID, now.Add(-24*time.Hour))
		if err != nil {
			return nil, err
		}
		pending, err := s.accessRequests.CountPendingAccessRequests(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if n >= MaxAccessRequestsPerMemberPerDay || pending >= MaxPendingAccessRequests {
			return nil, ErrAccessRequestLimit
		}
	}
	uid := userID
	ar := &mcpoauth.AccessRequest{
		ID: shared.NewID(), TenantID: tenantID, ClientHost: host, ClientName: req.Client.Name, ClientID: req.Client.ClientID,
		Scopes: req.Scopes, RequestedBy: &uid, Status: mcpoauth.AccessRequestPending, CreatedAt: now, UpdatedAt: now, RequestCount: 1,
	}
	created, err := s.accessRequests.UpsertAccessRequest(ctx, ar)
	if err != nil {
		return nil, err
	}
	if created {
		s.logAudit(ctx, tenantID.String(), userID.String(), actor,
			auditapp.NewSuccessEvent(auditdom.ActionMCPAccessRequested, auditdom.ResourceTypeMCPAccessRequest, ar.ID.String()).
				WithResourceName(req.Client.Name).
				WithMessage("Access requested for AI application publisher "+host).
				WithMetadata("client_host", host).
				WithMetadata("client_id", req.Client.ClientID).
				WithMetadata("scopes", mcpoauth.Join(req.Scopes)))
		s.notifyAdmins(ctx, tenantID, userID, ar)
	}
	return ar, nil
}

// ListAccessRequests lists the organization's pending requests whose
// publisher is not allowed yet.
func (s *Service) ListAccessRequests(ctx context.Context, tenantID shared.ID) ([]mcpoauth.AccessRequest, error) {
	if s.accessRequests == nil {
		return []mcpoauth.AccessRequest{}, nil
	}
	list, err := s.accessRequests.ListPendingAccessRequests(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	pol, err := s.policy(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read mcp policy: %w", err)
	}
	out := make([]mcpoauth.AccessRequest, 0, len(list))
	for _, a := range list {
		if !slices.Contains(pol.ClientHosts, a.ClientHost) && !slices.Contains(s.trustedHosts, a.ClientHost) {
			out = append(out, a)
		}
	}
	return out, nil
}

// ApproveAccessRequest approves the publisher of a pending request of the
// organization: the host is added to the policy (audited by the policy
// writer), the request is closed and the requester told.
func (s *Service) ApproveAccessRequest(ctx context.Context, tenantID, id, userID shared.ID, actor Actor) error {
	if s.accessRequests == nil || s.policyWriter == nil {
		return ErrAccessRequestsUnavailable
	}
	ar, err := s.accessRequests.GetAccessRequest(ctx, tenantID, id)
	if err != nil {
		return mcpoauth.ErrNotFound
	}
	if ar.Status != mcpoauth.AccessRequestPending {
		return mcpoauth.ErrNotFound
	}
	if err := s.policyWriter.AllowMCPClientHost(ctx, tenantID.String(), ar.ClientHost, auditContext(userID, actor)); err != nil {
		return err
	}
	return s.closeAccessRequest(ctx, ar, userID, true, actor)
}

// DenyAccessRequest declines a pending request of the organization.
func (s *Service) DenyAccessRequest(ctx context.Context, tenantID, id, userID shared.ID, actor Actor) error {
	if s.accessRequests == nil {
		return ErrAccessRequestsUnavailable
	}
	ar, err := s.accessRequests.GetAccessRequest(ctx, tenantID, id)
	if err != nil || ar.Status != mcpoauth.AccessRequestPending {
		return mcpoauth.ErrNotFound
	}
	return s.closeAccessRequest(ctx, ar, userID, false, actor)
}

// AllowPublisherFromConsent lets an administrator approve, from the consent
// page, the publisher of the application they are connecting: the same
// effect as approving a request for it.
func (s *Service) AllowPublisherFromConsent(ctx context.Context, requestID, userID, tenantID shared.ID, actor Actor) error {
	if s.policyWriter == nil {
		return ErrAccessRequestsUnavailable
	}
	req, err := s.repo.ClaimRequest(ctx, requestID, userID, s.now())
	if err != nil || req.Client.BlockedAt != nil {
		return ErrConsentUnavailable
	}
	pol, err := s.policy(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("read mcp policy: %w", err)
	}
	host, ok := s.requestablePublisher(pol, req.Client, tenantID)
	if !ok {
		return ErrAccessRequestNotPossible
	}
	if err := s.policyWriter.AllowMCPClientHost(ctx, tenantID.String(), host, auditContext(userID, actor)); err != nil {
		return err
	}
	if s.accessRequests != nil {
		if ar, err := s.accessRequests.PendingAccessRequestForHost(ctx, tenantID, host); err == nil {
			return s.closeAccessRequest(ctx, ar, userID, true, actor)
		}
	}
	return nil
}

func (s *Service) closeAccessRequest(ctx context.Context, ar *mcpoauth.AccessRequest, userID shared.ID, approve bool, actor Actor) error {
	if err := s.accessRequests.DecideAccessRequest(ctx, ar.TenantID, ar.ID, userID, approve, s.now()); err != nil {
		return err
	}
	action, title, msg := auditdom.ActionMCPAccessDenied, "AI application request declined", "Access request declined for "
	if approve {
		action, title, msg = auditdom.ActionMCPAccessApproved, "AI application approved", "Access request approved for "
	}
	s.logAudit(ctx, ar.TenantID.String(), userID.String(), actor,
		auditapp.NewSuccessEvent(action, auditdom.ResourceTypeMCPAccessRequest, ar.ID.String()).
			WithResourceName(ar.ClientName).
			WithMessage(msg+ar.ClientHost).
			WithMetadata("client_host", ar.ClientHost))
	if ar.RequestedBy != nil && *ar.RequestedBy != userID {
		body := fmt.Sprintf("Your organization declined applications published by %s.", ar.ClientHost)
		if approve {
			body = fmt.Sprintf("Applications published by %s can now be connected. Connect %s again.", ar.ClientHost, ar.ClientName)
		}
		s.notify(ctx, ar.TenantID, *ar.RequestedBy, userID, title, body, "/account/connected-apps")
	}
	return nil
}

func (s *Service) notifyAdmins(ctx context.Context, tenantID, requester shared.ID, ar *mcpoauth.AccessRequest) {
	if s.notifier == nil {
		return
	}
	admins, err := s.accessRequests.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.log.Warn("mcp access request: list admins", "error", err.Error())
		return
	}
	body := fmt.Sprintf("A member asks to connect %s, published by %s. Review it in AI assistants settings.", ar.ClientName, ar.ClientHost)
	for _, a := range admins {
		if a != requester {
			s.notify(ctx, tenantID, a, requester, "AI application access requested", body, "/settings/mcp?tab=applications")
		}
	}
}

func (s *Service) notify(ctx context.Context, tenantID, to, actor shared.ID, title, body, link string) {
	if s.notifier == nil {
		return
	}
	uid, aid := to, actor
	if err := s.notifier.Notify(ctx, notificationdom.NotificationParams{
		TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
		NotificationType: notificationdom.TypeMCPAccessRequest, Title: title, Body: body, Severity: "medium",
		URL: link, ActorID: &aid,
	}); err != nil {
		s.log.Warn("mcp access request: notify", "error", err.Error())
	}
}

func auditContext(userID shared.ID, actor Actor) auditapp.AuditContext {
	return auditapp.AuditContext{ActorID: userID.String(), ActorIP: actor.IP, UserAgent: actor.UserAgent, RequestID: actor.RequestID}
}

// consentPublisherState fills what the consent page needs to offer a way
// out of a blocked application: whether the caller may approve the
// publisher, and whether a request for it is already waiting.
func (s *Service) consentPublisherState(ctx context.Context, view *ConsentView, pol tenantdom.MCPSettings, c mcpoauth.Client, tenantID shared.ID, all bool, held []string) {
	host, ok := s.requestablePublisher(pol, c, tenantID)
	if !ok {
		return
	}
	view.Requestable = s.accessRequests != nil
	view.CanAllow = s.policyWriter != nil && (all || slices.Contains(held, string(permission.SettingsWrite)))
	if s.accessRequests != nil {
		if _, err := s.accessRequests.PendingAccessRequestForHost(ctx, tenantID, host); err == nil {
			view.AccessRequested = true
		}
	}
}
