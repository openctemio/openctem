package auth

// Linking an organization's single sign-on (OIDC: Entra ID, Okta, Google
// Workspace) to an existing account. See
// docs/architecture/sso-authentication.md, "Linking an existing account".
//
// A federated sign-in never adopts a password account on the strength of a
// matching email (adoptExistingUser refuses with ACCOUNT_LINK_REQUIRED). This
// file is the way such an account gets the organization's sign-in: the
// signed-in person starts the link from Account > Security with a proof typed
// for it (link_proof.go: the authenticator code, else the password; a recent
// sign-in does not count), signs in at the organization's identity provider
// (asked to authenticate again: max_age=0, and auth_time is checked on the
// way back), and the verified (issuer, subject) is bound to that account.
//
// The link reuses the sign-in round trip (GenerateAuthorizeURL, consumeState,
// redeemFederatedIdentity: PKCE, nonce, browser binding, single-use state)
// and keeps what makes it a link in its own single-use record next to the
// state: the account, the session that started it, the organization, the
// provider, the redirect_uri and the factor that proved it. The sign-in
// callback refuses a state that has a link record, and the link callback
// refuses one that has none.
//
// The link binds the identity only when, at completion: the request comes
// from the same account and the same session as the start, that session is
// still active, the account is active and an active member of the
// organization, the identity is not bound to another account, and the
// account holds no other subject at that issuer. The provider's email need
// not match the account's: the person proved both. No session is issued; the
// account's other sessions are revoked, the link is audited (in the account's
// and the organization's audit log) and the account's mailbox is told.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// ssoLinkDeps is what the identity link needs beyond the sign-in. The proof
// and the session revoker are required: without them every link and unlink
// is refused.
type ssoLinkDeps struct {
	proof    LinkProofVerifier
	sessions SessionRevoker
	notifier IdentityNotifier
}

// SetLinkProofVerifier wires the proof every SSO link and unlink needs.
func (s *SSOService) SetLinkProofVerifier(v LinkProofVerifier) { s.link.proof = v }

// SetSessionRevoker wires the revocation of the account's other sessions on
// every SSO link and unlink.
func (s *SSOService) SetSessionRevoker(r SessionRevoker) { s.link.sessions = r }

// SetIdentityNotifier wires the link and unlink e-mails.
func (s *SSOService) SetIdentityNotifier(n IdentityNotifier) { s.link.notifier = n }

// errSSOLinkNotWired refuses a link or unlink whose dependencies are missing.
var errSSOLinkNotWired = errors.New("organization sign-in linking is not configured")

func (s *SSOService) linkReady() bool {
	return s.link.proof != nil && s.link.sessions != nil && s.identities != nil
}

// ssoLinkRecord is kept for one link round trip under the hash of its state.
type ssoLinkRecord struct {
	UserID      string `json:"uid"`
	SessionID   string `json:"sid"`
	TenantID    string `json:"tid"`
	Provider    string `json:"p"`
	RedirectURI string `json:"ru"`
	Factor      string `json:"f"`
}

func ssoLinkKey(state string) string { return "sso_link:" + hashBinding(state) }

// takeLinkRecord removes and returns the link record of state: (nil, nil)
// when the state is not a link (or its record expired or was taken). A state
// store that cannot answer is an error, never "not a link": the sign-in
// callback would otherwise treat a link state as an ordinary sign-in.
func (s *SSOService) takeLinkRecord(ctx context.Context, state string) (*ssoLinkRecord, error) {
	if state == "" {
		return nil, nil
	}
	raw, found, err := s.stateStoreOrMemory().GetDel(ctx, ssoLinkKey(state))
	if err != nil {
		s.logger.Error("read sso link record", "error", err)
		return nil, fmt.Errorf("read sso link record: %w", err)
	}
	if !found {
		return nil, nil
	}
	var rec ssoLinkRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, fmt.Errorf("decode sso link record: %w", err)
	}
	return &rec, nil
}

// linkMember loads the active account userID and checks it is an active
// member of t (not offboarded, suspended or awaiting approval). Fail closed.
func (s *SSOService) linkMember(ctx context.Context, userID string, t *tenantdom.Tenant) (*userdom.User, error) {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return nil, ErrSSOInvalidState
	}
	u, err := s.userRepo.GetByID(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}
	if !u.IsActive() {
		return nil, ErrAccountSuspended
	}
	if t == nil || s.tenantMemberRepo == nil {
		return nil, ErrSSONotAMember
	}
	m, err := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID())
	if err != nil || m == nil || !m.IsActive() {
		return nil, ErrSSONotAMember
	}
	return u, nil
}

// SSOLinkStartInput starts linking an organization's sign-in to the
// signed-in account.
type SSOLinkStartInput struct {
	UserID      string
	SessionID   string
	OrgSlug     string
	Provider    string
	RedirectURI string
	// Proof is the code or password typed in the confirm dialog.
	Proof StepUpProof
}

// StartSSOLink checks the proof and returns the identity provider's
// authorization URL (with max_age=0) for a link round trip.
func (s *SSOService) StartSSOLink(ctx context.Context, in SSOLinkStartInput) (*SSOAuthorizeResult, error) {
	if !s.linkReady() {
		return nil, errSSOLinkNotWired
	}
	if in.UserID == "" || in.SessionID == "" {
		return nil, ErrLinkProofUnavailable
	}
	if err := s.validateRedirectURI(in.RedirectURI); err != nil {
		return nil, err
	}
	// An unknown organization answers like one the account is not a member of.
	t, err := s.tenantRepo.GetBySlug(ctx, in.OrgSlug)
	if err != nil {
		return nil, ErrSSONotAMember
	}
	u, err := s.linkMember(ctx, in.UserID, t)
	if err != nil {
		return nil, err
	}
	if _, err := s.resolveProvider(ctx, t.ID().String(), t.Slug(), identityproviderdom.Provider(in.Provider)); err != nil {
		return nil, err
	}
	ci := clientInfoFrom(ctx)
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: ci.IP, UserAgent: ci.UserAgent}
	factor, err := s.link.proof.VerifyLinkProof(ctx, actx, in.UserID, in.SessionID, in.Proof, LinkProofLinkStart)
	if err != nil {
		return nil, err
	}
	res, err := s.GenerateAuthorizeURL(ctx, SSOAuthorizeInput{
		OrgSlug: t.Slug(), Provider: in.Provider, RedirectURI: in.RedirectURI, ForceReauth: true,
	})
	if err != nil {
		return nil, err
	}
	rec, err := json.Marshal(ssoLinkRecord{
		UserID: in.UserID, SessionID: in.SessionID, TenantID: t.ID().String(),
		Provider: in.Provider, RedirectURI: in.RedirectURI, Factor: string(factor),
	})
	if err != nil {
		return nil, err
	}
	if err := s.stateStoreOrMemory().Set(ctx, ssoLinkKey(res.State), string(rec), ssoStateTTL); err != nil {
		return nil, fmt.Errorf("store sso link: %w", err)
	}
	return res, nil
}

// SSOLinkCompleteInput finishes a link started by StartSSOLink.
type SSOLinkCompleteInput struct {
	UserID    string
	SessionID string
	Provider  string
	Code      string
	State     string
	// BrowserBinding is the secret StartSSOLink returned to this browser.
	BrowserBinding string
}

// SSOLink is an organization sign-in linked to the account.
type SSOLink struct {
	IdentityID string    `json:"identity_id"`
	OrgSlug    string    `json:"org_slug"`
	Provider   string    `json:"provider"`
	CreatedAt  time.Time `json:"created_at"`
}

// CompleteSSOLink verifies the identity provider's answer and binds the
// identity to the account that started the link.
func (s *SSOService) CompleteSSOLink(ctx context.Context, in SSOLinkCompleteInput) (*SSOLink, error) {
	if !s.linkReady() {
		return nil, errSSOLinkNotWired
	}
	if in.UserID == "" || in.SessionID == "" {
		return nil, ErrSSOInvalidState
	}
	// The state and its link record are spent first, so a refused completion
	// cannot be retried.
	st, err := s.consumeState(ctx, in.State, in.BrowserBinding)
	if err != nil {
		_, _ = s.takeLinkRecord(ctx, in.State)
		return nil, ErrSSOInvalidState
	}
	rec, err := s.takeLinkRecord(ctx, in.State)
	if err != nil {
		return nil, ErrSSOInvalidState
	}
	if !rec.matches(in, st) {
		s.logger.Warn("SSO link refused: the state is not a link of this account and session", "provider", in.Provider)
		return nil, ErrSSOInvalidState
	}
	factor := StepUpMethod(rec.Factor)
	if err := s.requireLiveSession(ctx, in.UserID, in.SessionID); err != nil {
		return nil, err
	}
	got, err := s.redeemFederatedIdentity(ctx, st, in.Provider, in.Code, rec.RedirectURI)
	if err != nil {
		return nil, err
	}
	t := got.tenant
	if t.ID().String() != rec.TenantID {
		return nil, ErrSSOInvalidState
	}
	u, err := s.linkMember(ctx, in.UserID, t)
	if err != nil {
		return nil, err
	}
	ident, err := s.bindLinkedIdentity(ctx, u, t, got.info, in.SessionID)
	if err != nil {
		return nil, err
	}
	// The person just authenticated at the organization's identity provider:
	// that is the sign-in the Require SSO precondition asks of an owner or
	// administrator.
	if s.signIns != nil {
		if err := s.signIns.RecordSSOSignIn(ctx, t.ID(), u.ID()); err != nil {
			s.logger.Warn("record organization sign-in of a link", "error", err)
		}
	}
	label := ssoLinkLabel(t, got.rp)
	s.auditSSOIdentity(ctx, u, t, auditdom.ActionAuthIdentityLinked,
		"Linked "+label+" to the account", in.Provider, factor)
	if s.link.notifier != nil {
		s.link.notifier.NotifyIdentityLinked(ctx, u.Email(), u.Name(), clientInfoFrom(ctx).IP, label)
	}
	return &SSOLink{IdentityID: ident.ID.String(), OrgSlug: t.Slug(), Provider: in.Provider, CreatedAt: ident.CreatedAt}, nil
}

// matches reports whether a link record belongs to this completion: the same
// account, session and provider, a state that asked for a fresh
// authentication, and a start that was proved.
func (r *ssoLinkRecord) matches(in SSOLinkCompleteInput, st ssoState) bool {
	if r == nil {
		return false
	}
	f := StepUpMethod(r.Factor)
	return r.UserID == in.UserID && r.SessionID == in.SessionID &&
		r.Provider == in.Provider && st.provider == in.Provider && st.reauth &&
		(f == StepUpTOTP || f == StepUpPassword)
}

// bindLinkedIdentity binds the verified identity to u: refused when it is
// another account's, or when u already holds another subject at the issuer.
// The account's other sessions are revoked first (fail closed).
func (s *SSOService) bindLinkedIdentity(ctx context.Context, u *userdom.User, t *tenantdom.Tenant, info *SSOUserInfo, keepSessionID string) (*useridentity.Identity, error) {
	key := useridentity.Key{Issuer: info.Issuer, Subject: info.Subject}
	if !key.Valid() {
		return nil, ErrSSOInvalidIDToken
	}
	acc := s.accounts()
	owner, _, err := acc.lookup(ctx, key, info.LegacySubject)
	if err != nil {
		return nil, fmt.Errorf("resolve federated identity: %w", err)
	}
	if owner != nil && owner.ID() != u.ID() {
		s.logger.Warn("SSO link refused: the identity is bound to another account",
			"user_id", u.ID().String(), "tenant_id", t.ID().String())
		return nil, ErrIdentityLinkedElsewhere
	}
	sameIssuer, _, err := acc.boundIdentities(ctx, u, key)
	if err != nil {
		return nil, fmt.Errorf("check federated identities: %w", err)
	}
	if sameIssuer {
		return nil, ErrProviderAlreadyLinked
	}
	// The account's other sessions end before the new sign-in method exists;
	// the session that proved the link keeps going.
	if err := s.link.sessions.RevokeAllSessions(ctx, u.ID().String(), keepSessionID); err != nil {
		return nil, fmt.Errorf("revoke other sessions before the link: %w", err)
	}
	if err := acc.bind(ctx, u, key); err != nil {
		if errors.Is(err, ErrFederatedIdentityConflict) {
			return nil, ErrIdentityLinkedElsewhere
		}
		return nil, err
	}
	ident, err := s.identities.GetByKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read linked identity: %w", err)
	}
	return ident, nil
}

// requireLiveSession checks sessionID is an active session of userID.
func (s *SSOService) requireLiveSession(ctx context.Context, userID, sessionID string) error {
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return ErrSSOInvalidState
	}
	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil || sess == nil || !sess.IsActive() || sess.UserID().String() != userID {
		return ErrSSOInvalidState
	}
	return nil
}

// ssoLinkLabel names an organization's sign-in for e-mails and audit.
func ssoLinkLabel(t *tenantdom.Tenant, rp *resolvedProvider) string {
	name := "single sign-on"
	if rp != nil && strings.TrimSpace(rp.displayName) != "" {
		name = strings.TrimSpace(rp.displayName)
	}
	return t.Name() + " (" + name + ")"
}

// auditSSOIdentity records an SSO link or unlink. A link is also written to
// the organization's audit log (t set): its member's sign-in methods changed.
func (s *SSOService) auditSSOIdentity(ctx context.Context, u *userdom.User, t *tenantdom.Tenant, action auditdom.Action, msg, provider string, factor StepUpMethod) {
	if s.audit == nil {
		return
	}
	ci := clientInfoFrom(ctx)
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage(msg).
		WithMetadata("provider", "sso:"+provider).
		WithMetadata("how", linkHowManual)
	if factor != "" {
		ev = ev.WithMetadata("factor", string(factor))
	}
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: ci.IP, UserAgent: ci.UserAgent}
	if t != nil {
		actx.TenantID = t.ID().String()
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to audit identity change", "action", string(action), "error", err)
	}
}

// SSOLinkOrganization is one organization of the account with single
// sign-on, for Account > Security.
type SSOLinkOrganization struct {
	OrgSlug     string `json:"org_slug"`
	OrgName     string `json:"org_name"`
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
	// Identity is the account's identity at this provider, nil when the
	// organization's sign-in is not linked.
	Identity *SSOLinkedIdentity `json:"identity,omitempty"`
}

// SSOLinkedIdentity is an organization sign-in identity of the account.
type SSOLinkedIdentity struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Unlinkable: the person may remove it here (an OIDC identity of an
	// account with a password, which keeps a way to sign in).
	Unlinkable bool `json:"unlinkable"`
}

// SSOLinks is the account's organization sign-in, for Account > Security.
type SSOLinks struct {
	Organizations []SSOLinkOrganization `json:"organizations"`
	// Other: organization sign-in identities not matched to an organization
	// listed above (a former organization, or SAML).
	Other []SSOLinkedIdentity `json:"other"`
	// Proof is what a link or unlink asks for: totp, password, or "" when
	// the account must turn on two-factor authentication first.
	Proof string `json:"proof"`
}

// ListSSOLinks lists the organizations of userID that have an OIDC single
// sign-on, with the account's identity at each. Only the caller's own account
// and its own active memberships are read.
func (s *SSOService) ListSSOLinks(ctx context.Context, userID string) (*SSOLinks, error) {
	if s.identities == nil {
		return nil, errIdentityStoreMissing
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	u, err := s.userRepo.GetByID(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}
	idents, err := s.identities.ListByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	orgs, err := s.tenantRepo.ListTenantsByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	hasPassword := isPasswordAccount(u)
	out := &SSOLinks{Organizations: []SSOLinkOrganization{}, Other: []SSOLinkedIdentity{}}
	if s.link.proof != nil {
		if m, perr := s.link.proof.LinkProofMethod(ctx, userID); perr == nil {
			out.Proof = string(m)
		}
	}
	matched := map[shared.ID]bool{}
	for _, tw := range orgs {
		if tw == nil || tw.Tenant == nil {
			continue
		}
		rows := s.organizationLinkRows(ctx, userID, tw.Tenant, idents, hasPassword, matched)
		out.Organizations = append(out.Organizations, rows...)
	}
	for _, ident := range idents {
		if ident.ManagedBySSO() && !matched[ident.ID] {
			v := linkedIdentityView(ident, hasPassword)
			out.Other = append(out.Other, *v)
		}
	}
	return out, nil
}

// organizationLinkRows is t's OIDC providers with the account's identity at
// each; none when the account is not an active member of t.
func (s *SSOService) organizationLinkRows(ctx context.Context, userID string, t *tenantdom.Tenant,
	idents []*useridentity.Identity, hasPassword bool, matched map[shared.ID]bool) []SSOLinkOrganization {
	if _, err := s.linkMember(ctx, userID, t); err != nil {
		return nil
	}
	providers, err := s.GetProvidersForTenant(ctx, t.Slug())
	if err != nil {
		s.logger.Warn("list organization providers for sign-in links", "tenant_id", t.ID().String(), "error", err)
		return nil
	}
	rows := make([]SSOLinkOrganization, 0, len(providers))
	for _, p := range providers {
		row := SSOLinkOrganization{OrgSlug: t.Slug(), OrgName: t.Name(), Provider: p.Provider, DisplayName: p.DisplayName}
		dir := s.providerDirectory(ctx, t, p)
		for _, ident := range idents {
			if identityOfProvider(identityproviderdom.Provider(p.Provider), dir, ident) {
				matched[ident.ID] = true
				row.Identity = linkedIdentityView(ident, hasPassword)
				break
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func linkedIdentityView(ident *useridentity.Identity, hasPassword bool) *SSOLinkedIdentity {
	return &SSOLinkedIdentity{
		ID: ident.ID.String(), CreatedAt: ident.CreatedAt, LastUsedAt: ident.LastUsedAt,
		Unlinkable: hasPassword && ident.Key.ScopeTenantID == nil,
	}
}

// providerDirectory is the tenant identifier (Entra directory, Okta org URL)
// of an organization's provider as listed by GetProvidersForTenant.
func (s *SSOService) providerDirectory(ctx context.Context, t *tenantdom.Tenant, p SSOProviderInfo) string {
	prov := identityproviderdom.Provider(p.Provider)
	if strings.HasPrefix(p.ID, "env:") {
		if rp := s.envProvider(t.Slug(), prov); rp != nil {
			return rp.tenantIdentifier
		}
		return ""
	}
	ip, err := s.ipRepo.GetByTenantAndProvider(ctx, t.ID().String(), prov)
	if err != nil {
		return ""
	}
	return ip.TenantIdentifier()
}

// identityOfProvider reports whether ident is an organization sign-in
// identity this provider could have asserted, by the provider's issuer rule.
// Display only: it decides what Account > Security shows as linked.
func identityOfProvider(p identityproviderdom.Provider, tenantIdentifier string, ident *useridentity.Identity) bool {
	if ident == nil || !ident.ManagedBySSO() || ident.Key.ScopeTenantID != nil {
		return false
	}
	c := &oidc.Claims{}
	c.Issuer = ident.Key.Issuer
	switch p {
	case identityproviderdom.ProviderEntraID:
		const pre, suf = "https://login.microsoftonline.com/", "/v2.0"
		if !strings.HasPrefix(c.Issuer, pre) || !strings.HasSuffix(c.Issuer, suf) {
			return false
		}
		c.TID = strings.TrimSuffix(strings.TrimPrefix(c.Issuer, pre), suf)
		return oidc.EntraIssuer(tenantIdentifier)(c) == nil
	case identityproviderdom.ProviderOkta:
		return tenantIdentifier != "" && oidc.OktaIssuer(tenantIdentifier)(c) == nil
	case identityproviderdom.ProviderGoogleWorkspace:
		return oidc.GoogleIssuer(c) == nil
	}
	return false
}

// SSOUnlinkInput removes an organization sign-in identity from the signed-in
// account.
type SSOUnlinkInput struct {
	UserID     string
	SessionID  string
	IdentityID string
	// Proof is the code or password typed in the confirm dialog.
	Proof StepUpProof
}

// UnlinkSSOIdentity removes an organization's OIDC sign-in identity from the
// signed-in account after checking the proof typed for it. Only an account
// with a password may: it keeps a way to sign in, and an account the
// organization's sign-on created stays managed by the organization.
func (s *SSOService) UnlinkSSOIdentity(ctx context.Context, in SSOUnlinkInput) error {
	if !s.linkReady() {
		return errSSOLinkNotWired
	}
	if in.UserID == "" || in.SessionID == "" {
		return ErrLinkProofUnavailable
	}
	uid, err := shared.IDFromString(in.UserID)
	if err != nil {
		return ErrIdentityNotFound
	}
	u, err := s.userRepo.GetByID(ctx, uid)
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}
	if !u.IsActive() {
		return ErrAccountSuspended
	}
	idents, err := s.identities.ListByUser(ctx, uid)
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}
	var target *useridentity.Identity
	for _, ident := range idents {
		if ident.ID.String() == in.IdentityID {
			target = ident
		}
	}
	if target == nil || !target.ManagedBySSO() {
		return ErrIdentityNotFound
	}
	if target.Key.ScopeTenantID != nil || !isPasswordAccount(u) {
		return ErrIdentityNotUnlinkable
	}
	ci := clientInfoFrom(ctx)
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: ci.IP, UserAgent: ci.UserAgent}
	factor, err := s.link.proof.VerifyLinkProof(ctx, actx, in.UserID, in.SessionID, in.Proof, LinkProofUnlink)
	if err != nil {
		return err
	}
	// A session opened through the organization's sign-in must not outlive
	// the unlink. Revoke first and fail closed.
	if err := s.link.sessions.RevokeAllSessions(ctx, u.ID().String(), in.SessionID); err != nil {
		return fmt.Errorf("revoke other sessions before the unlink: %w", err)
	}
	if err := s.identities.DeleteForUser(ctx, u.ID(), target.ID, false); err != nil {
		if errors.Is(err, useridentity.ErrNotFound) {
			return ErrIdentityNotFound
		}
		return fmt.Errorf("unlink identity: %w", err)
	}
	const label = "organization single sign-on"
	s.auditSSOIdentity(ctx, u, nil, auditdom.ActionAuthIdentityUnlinked, "Unlinked "+label+" from the account", "oidc", factor)
	if s.link.notifier != nil {
		s.link.notifier.NotifyIdentityUnlinked(ctx, u.Email(), u.Name(), ci.IP, label)
	}
	return nil
}
