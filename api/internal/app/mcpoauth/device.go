package mcpoauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The device authorization grant (RFC 8628) for terminals whose browser is
// on another machine: an SSH session, a container, a remote desktop. The
// terminal shows a short user code; the person enters it in any signed-in
// browser and decides on the usual consent page (with a recent sign-in);
// the terminal polls the token endpoint with its device code.
//
// Design: docs/rfcs/RFC-062-mcp-authorization.md (section 6a).

// DeviceVerificationPath is the web page where the person enters the code.
const DeviceVerificationPath = "/oauth/device"

// BlockedDeviceFlowDisabled: the organization does not allow terminal
// sign-in with a user code.
const BlockedDeviceFlowDisabled = "device_flow_disabled"

// ErrUserCodeInvalid is every user code that cannot be used: malformed,
// unknown, expired, already decided or entered by someone else. One error,
// so codes cannot be probed.
var ErrUserCodeInvalid = fmt.Errorf("%w: the code is not valid", shared.ErrNotFound)

// ErrDeviceFlowDisabled: the organization does not allow terminal sign-in.
var ErrDeviceFlowDisabled = fmt.Errorf("%w: your organization does not allow signing in a terminal with a code", shared.ErrForbidden)

// ErrDeviceFullData: a connection signed in with a terminal code never gets
// access to all organization data.
var ErrDeviceFullData = fmt.Errorf("%w: access to all organization data cannot be given to a terminal sign-in", shared.ErrForbidden)

// DeviceAuthorizationResponse is the RFC 8628 §3.2 response. There is no
// verification_uri_complete: the person always types the code the terminal
// shows, so a link alone cannot get anyone to approve a stranger's request.
type DeviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// maxUserAgentLen bounds the requester's user agent kept for the consent page.
const maxUserAgentLen = 256

// StartDeviceAuthorization handles POST /oauth/device_authorization: it
// stores a device request and returns its codes. Only a client the platform
// or an organization registered may use the device grant: a metadata
// document or dynamically registered client is identified by its redirect
// URIs, which this grant does not use, so its name could not be trusted.
func (s *Service) StartDeviceAuthorization(ctx context.Context, form url.Values, actor Actor) (*DeviceAuthorizationResponse, *OAuthError) {
	for k, v := range form {
		if len(v) > 1 {
			return nil, oauthErr("invalid_request", "parameter "+k+" repeated")
		}
	}
	clientID := form.Get("client_id")
	if clientID == "" || len(clientID) > maxClientIDLen {
		return nil, oauthErr("invalid_request", "client_id is required")
	}
	client, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil || client.BlockedAt != nil {
		return nil, oauthErr("invalid_client", "unknown or unusable client")
	}
	if client.Kind != mcpoauth.ClientKindOrganization {
		return nil, oauthErr("unauthorized_client", "this client may not use the device grant; use "+mcpoauth.DeviceClientID)
	}
	if r := form.Get("resource"); r != "" && !s.isResource(r) {
		return nil, oauthErr("invalid_target", "resource must be "+s.endpoints.Resource)
	}
	scopes, perr := mcpoauth.ParseScopes(form.Get("scope"))
	if perr != nil {
		return nil, oauthErr("invalid_scope", "unknown scope")
	}
	if len(scopes) == 0 {
		scopes = mcpoauth.ReadScopes()
	}
	now := s.now()
	// A user code collision is astronomically rare but would fail the
	// unique index: draw again.
	for range 3 {
		deviceCode, derr := randomToken(mcpoauth.DeviceCodePrefix)
		if derr != nil {
			return nil, oauthErr("server_error", "try again")
		}
		userCode, uerr := mcpoauth.NewUserCode()
		if uerr != nil {
			return nil, oauthErr("server_error", "try again")
		}
		req := &mcpoauth.AuthRequest{
			ID:                 shared.NewID(),
			Flow:               mcpoauth.FlowDevice,
			Client:             *client,
			Resource:           s.endpoints.Resource,
			Scopes:             scopes,
			Status:             mcpoauth.RequestPending,
			DeviceCodeHash:     s.hash(deviceCode),
			UserCodeHash:       s.hash(mcpoauth.NormalizeUserCode(userCode)),
			PollInterval:       mcpoauth.DevicePollInterval,
			RequesterIP:        actor.IP,
			RequesterUserAgent: cleanUserAgent(actor.UserAgent),
			CreatedAt:          now,
			ExpiresAt:          now.Add(mcpoauth.DeviceRequestTTL),
		}
		if err := s.repo.CreateRequest(ctx, req); err != nil {
			s.log.Warn("mcp oauth: store device request", "error", err.Error())
			continue
		}
		return &DeviceAuthorizationResponse{
			DeviceCode:      deviceCode,
			UserCode:        userCode,
			VerificationURI: s.endpoints.Issuer + DeviceVerificationPath,
			ExpiresIn:       int(mcpoauth.DeviceRequestTTL.Seconds()),
			Interval:        int(mcpoauth.DevicePollInterval.Seconds()),
		}, nil
	}
	return nil, oauthErr("server_error", "try again")
}

// cleanUserAgent keeps printable ASCII only (a user agent is caller input
// shown on the consent page and written to the audit trail) and bounds it.
func cleanUserAgent(ua string) string {
	var sb strings.Builder
	for _, r := range ua {
		if r >= 0x20 && r < 0x7f {
			sb.WriteRune(r)
		}
		if sb.Len() >= maxUserAgentLen {
			break
		}
	}
	return strings.TrimSpace(sb.String())
}

// EnterUserCode binds the device request behind a user code to the
// signed-in person and returns its id; the consent page then shows it. The
// organization the session works in must allow terminal sign-in. Attempts
// are limited per address and per person on the route.
func (s *Service) EnterUserCode(ctx context.Context, userCode string, userID, tenantID shared.ID) (shared.ID, error) {
	code := mcpoauth.NormalizeUserCode(userCode)
	if code == "" {
		return shared.ID{}, ErrUserCodeInvalid
	}
	pol, err := s.policy(ctx, tenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("read mcp policy: %w", err)
	}
	if pol.Disabled || pol.DeviceFlowDisabled {
		return shared.ID{}, ErrDeviceFlowDisabled
	}
	req, err := s.repo.ClaimDeviceRequest(ctx, s.hash(code), userID, s.now())
	if err != nil {
		if !errors.Is(err, mcpoauth.ErrNotFound) {
			s.log.Error("mcp oauth: claim device request", "error", err.Error())
		}
		return shared.ID{}, ErrUserCodeInvalid
	}
	return req.ID, nil
}

// exchangeDeviceCode handles grant_type=urn:ietf:params:oauth:grant-type:device_code
// (RFC 8628 §3.4, §3.5).
func (s *Service) exchangeDeviceCode(ctx context.Context, form url.Values, dpopProof string, actor Actor) (*TokenResponse, *OAuthError) {
	invalid := oauthErr("invalid_grant", "the device code is invalid")
	raw, clientID := form.Get("device_code"), form.Get("client_id")
	if !strings.HasPrefix(raw, mcpoauth.DeviceCodePrefix) || clientID == "" {
		return nil, oauthErr("invalid_request", "device_code and client_id are required")
	}
	if r := form.Get("resource"); r != "" && !s.isResource(r) {
		return nil, oauthErr("invalid_target", "resource must be "+s.endpoints.Resource)
	}
	jkt, perr := s.tokenProof(ctx, dpopProof)
	if perr != nil {
		return nil, perr
	}
	now := s.now()
	req, poll, err := s.repo.PollDeviceCode(ctx, s.hash(raw), clientID, now)
	if err != nil {
		if !errors.Is(err, mcpoauth.ErrNotFound) {
			s.log.Error("mcp oauth: poll device code", "error", err.Error())
			return nil, oauthErr("server_error", "try again")
		}
		return nil, invalid
	}
	switch poll {
	case mcpoauth.DevicePending:
		return nil, oauthErr("authorization_pending", "the person has not decided yet")
	case mcpoauth.DeviceSlowDown:
		return nil, oauthErr("slow_down", "poll less often")
	case mcpoauth.DeviceDenied:
		return nil, oauthErr("access_denied", "the person refused")
	case mcpoauth.DeviceExpired:
		return nil, oauthErr("expired_token", "the device code expired; start again")
	case mcpoauth.DeviceReused:
		// A redeemed device code presented again: someone else holds a copy.
		// Revoke what the first redemption issued (RFC 9700 §4.2.4 by analogy).
		if req.GrantID != nil && req.TenantID != nil {
			_ = s.repo.RevokeGrant(ctx, *req.TenantID, *req.GrantID, mcpoauth.RevokedCodeReuse, now)
		}
		s.logAudit(ctx, idString(req.TenantID), idString(req.UserID), actor,
			auditapp.NewDeniedEvent(auditdom.ActionMCPCodeReused, auditdom.ResourceTypeMCPGrant, idString(req.GrantID), "device code reused").
				WithResourceName(req.Client.Name).
				WithMetadata("client_id", req.Client.ClientID).
				WithMetadata("flow", string(mcpoauth.FlowDevice)))
		return nil, invalid
	case mcpoauth.DeviceApproved:
	default:
		return nil, invalid
	}
	if req.Client.BlockedAt != nil || req.UserID == nil || req.TenantID == nil {
		return nil, invalid
	}
	return s.issueGrant(ctx, req, jkt, actor, now)
}

// deviceRefused reports whether the organization policy refuses a grant or
// request made with a terminal code.
func deviceRefused(p tenantdom.MCPSettings, flow mcpoauth.Flow) bool {
	return flow == mcpoauth.FlowDevice && p.DeviceFlowDisabled
}

// deviceAuditMetadata adds what identifies a device request to an audit event.
func deviceAuditMetadata(e auditapp.AuditEvent, req *mcpoauth.AuthRequest) auditapp.AuditEvent {
	if req.Flow != mcpoauth.FlowDevice {
		return e
	}
	return e.WithMetadata("flow", string(mcpoauth.FlowDevice)).
		WithMetadata("requester_ip", req.RequesterIP).
		WithMetadata("requester_user_agent", req.RequesterUserAgent)
}

// deviceConsentView adapts the consent page to a device request: the client
// is whatever the terminal says it is, so it is never shown as verified or
// published anywhere, there is no address to return to, and access to all
// organization data is not offered.
func (s *Service) deviceConsentView(view *ConsentView, req *mcpoauth.AuthRequest, pol tenantdom.MCPSettings) {
	view.Flow = mcpoauth.FlowDevice
	view.Verified = false
	view.ClientHost = ""
	view.RedirectURI = ""
	view.RedirectHost = ""
	view.LoopbackOnly = false
	view.FullDataAvailable = false
	view.Requestable, view.CanAllow, view.AccessRequested = false, false, false
	view.RequesterIP = req.RequesterIP
	view.RequesterUserAgent = req.RequesterUserAgent
	view.RequestedAt = req.CreatedAt
	if view.Blocked == "" && deviceRefused(pol, req.Flow) {
		view.Blocked = BlockedDeviceFlowDisabled
	}
}
