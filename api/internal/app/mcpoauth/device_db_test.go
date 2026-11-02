package mcpoauth_test

// The device authorization grant (RFC 8628, RFC-062 section 6a) over a
// migrated database: a terminal asks for codes, the person enters the user
// code in a signed-in session and approves, the terminal polls. With the
// attacks the design defends against: polling too fast, a code entered by a
// second person, a request claimed by its id, a device code replayed or
// used by another client, an unregistered client, a cross-tenant approval,
// full data access, and the organization switching the flow off.
//
// DB-gated: DATABASE_URL must point at a migrated *_test database.

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	mcpoauthdom "github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

var userCodeShape = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

// startDevice asks for codes as a terminal at ip.
func (h *harness) startDevice(client, ip string) *mcpoauth.DeviceAuthorizationResponse {
	h.t.Helper()
	resp, oerr := h.svc.StartDeviceAuthorization(context.Background(), url.Values{
		"client_id": {client}, "scope": {"mcp:findings.read mcp:pentest.read"}, "resource": {resource},
	}, mcpoauth.Actor{IP: ip, UserAgent: "test-terminal/1.0\x1b[31m"})
	if oerr != nil {
		h.t.Fatalf("device authorization: %v", oerr)
	}
	return resp
}

// poll polls the token endpoint as the terminal.
func (h *harness) poll(deviceCode, client string) (*mcpoauth.TokenResponse, *mcpoauth.OAuthError) {
	return h.svc.Token(context.Background(), url.Values{
		"grant_type": {mcpoauthdom.DeviceGrantType}, "device_code": {deviceCode}, "client_id": {client}, "resource": {resource},
	}, "", mcpoauth.Actor{})
}

// pollAfterInterval polls as if the interval had passed since the last poll.
func (h *harness) pollAfterInterval(deviceCode, client string) (*mcpoauth.TokenResponse, *mcpoauth.OAuthError) {
	h.exec(`UPDATE mcp_oauth_requests SET last_polled_at = last_polled_at - interval '2 minutes' WHERE flow = 'device' AND last_polled_at IS NOT NULL`)
	return h.poll(deviceCode, client)
}

func wantOAuth(t *testing.T, oerr *mcpoauth.OAuthError, code string) {
	t.Helper()
	if oerr == nil || oerr.Code != code {
		t.Fatalf("got %v, want %s", oerr, code)
	}
}

func TestDeviceFlowEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	user := h.member(h.tenant, "member", "findings:read")

	resp := h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.7")
	if !strings.HasPrefix(resp.DeviceCode, mcpoauthdom.DeviceCodePrefix) || !userCodeShape.MatchString(resp.UserCode) ||
		resp.VerificationURI != issuer+"/oauth/device" || resp.ExpiresIn != 600 || resp.Interval != 5 {
		t.Fatalf("device authorization response %+v", resp)
	}

	// Nobody decided yet; polling again at once is too fast.
	_, oerr := h.poll(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	wantOAuth(t, oerr, "authorization_pending")
	_, oerr = h.poll(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	wantOAuth(t, oerr, "slow_down")
	var interval int
	if err := h.db.QueryRow(`SELECT poll_interval_seconds FROM mcp_oauth_requests WHERE requester_ip = '203.0.113.7'`).Scan(&interval); err != nil || interval != 10 {
		t.Fatalf("interval after slow_down = %d (%v), want 10", interval, err)
	}

	// The person types the code as they read it (lower case, no dash).
	id, err := h.svc.EnterUserCode(ctx, strings.ToLower(strings.ReplaceAll(resp.UserCode, "-", " ")), user, tenant)
	if err != nil {
		t.Fatalf("enter user code: %v", err)
	}
	view, err := h.svc.ConsentRequest(ctx, id, user, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if view.Flow != mcpoauthdom.FlowDevice || view.RequesterIP != "203.0.113.7" || view.RequesterUserAgent != "test-terminal/1.0[31m" ||
		view.Verified || view.RedirectURI != "" || view.FullDataAvailable || view.Blocked != "" || view.RequestedAt.IsZero() {
		t.Fatalf("device consent view %+v", view)
	}
	to, err := h.svc.Approve(ctx, id, user, tenant, mcpoauth.Actor{})
	if err != nil || to != "" {
		t.Fatalf("approve: %q %v (a device approval has no redirect)", to, err)
	}

	tok, oerr := h.pollAfterInterval(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	if oerr != nil {
		t.Fatalf("poll after approval: %v", oerr)
	}
	if tok.Scope != "mcp:findings.read" || tok.TokenType != "Bearer" || tok.RefreshToken == "" {
		t.Fatalf("token response %+v", tok)
	}
	p, err := h.principal(tok.AccessToken)
	if err != nil || p.TenantID != h.tenant || p.UserID != user.String() || p.ClientID != mcpoauthdom.DeviceClientID || p.FullData {
		t.Fatalf("principal %+v %v", p, err)
	}
	var flow string
	if err := h.db.QueryRow(`SELECT flow FROM mcp_oauth_grants WHERE id = $1`, p.GrantID).Scan(&flow); err != nil || flow != "device" {
		t.Fatalf("grant flow %q %v", flow, err)
	}
	// It shows in the person's connections, marked as a terminal sign-in.
	conns, err := h.svc.ListConnections(ctx, tenant, &user)
	if err != nil || len(conns) != 1 || conns[0].Flow != mcpoauthdom.FlowDevice {
		t.Fatalf("connections %+v %v", conns, err)
	}
	// Refresh works like any grant.
	if _, oerr := h.svc.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {mcpoauthdom.DeviceClientID}}, "", mcpoauth.Actor{}); oerr != nil {
		t.Fatalf("refresh: %v", oerr)
	}

	// The device code presented again: someone else holds a copy. The grant
	// it created is revoked.
	_, oerr = h.pollAfterInterval(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	wantOAuth(t, oerr, "invalid_grant")
	if _, err := h.principal(tok.AccessToken); !errors.Is(err, mcpoauth.ErrInvalidToken) {
		t.Fatalf("grant survived device code reuse: %v", err)
	}
}

func TestDeviceFlowDeniedAndExpired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	user := h.member(h.tenant, "member", "findings:read")

	resp := h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.8")
	id, err := h.svc.EnterUserCode(ctx, resp.UserCode, user, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if to, err := h.svc.Deny(ctx, id, user, tenant, mcpoauth.Actor{}); err != nil || to != "" {
		t.Fatalf("deny: %q %v", to, err)
	}
	_, oerr := h.poll(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	wantOAuth(t, oerr, "access_denied")

	// Ten minutes later neither code is good any more.
	resp = h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.9")
	mcpoauth.SetClock(h.svc, func() time.Time { return time.Now().Add(11 * time.Minute) })
	if _, err := h.svc.EnterUserCode(ctx, resp.UserCode, user, tenant); !errors.Is(err, mcpoauth.ErrUserCodeInvalid) {
		t.Fatalf("expired user code accepted: %v", err)
	}
	_, oerr = h.poll(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	wantOAuth(t, oerr, "expired_token")
}

func TestUserCodeIsSingleUseAndRequestNotClaimableByID(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	alice := h.member(h.tenant, "member", "findings:read")
	mallory := h.member(h.tenant, "member", "findings:read")

	resp := h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.10")
	var rawID string
	if err := h.db.QueryRow(`SELECT id FROM mcp_oauth_requests WHERE requester_ip = '203.0.113.10'`).Scan(&rawID); err != nil {
		t.Fatal(err)
	}
	id := shared.MustIDFromString(rawID)
	// Knowing the request id is not enough: a device request is claimed only
	// by entering its user code.
	if _, err := h.svc.ConsentRequest(ctx, id, mallory, tenant); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("device request claimed by id: %v", err)
	}
	if _, err := h.svc.Approve(ctx, id, mallory, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("device request approved by id: %v", err)
	}
	if _, err := h.svc.EnterUserCode(ctx, resp.UserCode, alice, tenant); err != nil {
		t.Fatal(err)
	}
	// Alice entering it again is fine; anyone else gets nothing.
	if _, err := h.svc.EnterUserCode(ctx, resp.UserCode, alice, tenant); err != nil {
		t.Fatalf("re-entry by the same person: %v", err)
	}
	if _, err := h.svc.EnterUserCode(ctx, resp.UserCode, mallory, tenant); !errors.Is(err, mcpoauth.ErrUserCodeInvalid) {
		t.Fatalf("second person took the code: %v", err)
	}
	if _, err := h.svc.ConsentRequest(ctx, id, mallory, tenant); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("second person read the consent: %v", err)
	}
	for _, bad := range []string{"", "AAAA-AAAA", "BCDF-GHJ", resp.DeviceCode} {
		if _, err := h.svc.EnterUserCode(ctx, bad, alice, tenant); !errors.Is(err, mcpoauth.ErrUserCodeInvalid) {
			t.Fatalf("code %q: %v", bad, err)
		}
	}
}

func TestDeviceCodeOnlyRedeemsForItsClient(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	user := h.member(h.tenant, "member", "findings:read")
	resp := h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.11")
	id, err := h.svc.EnterUserCode(ctx, resp.UserCode, user, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, id, user, tenant, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	_, oerr := h.poll(resp.DeviceCode, clientID)
	wantOAuth(t, oerr, "invalid_grant")
	// The wrong client did not burn it.
	if _, oerr := h.poll(resp.DeviceCode, mcpoauthdom.DeviceClientID); oerr != nil {
		t.Fatalf("right client after a wrong one: %v", oerr)
	}
	// An authorization code is not a device code, and the reverse.
	_, oerr = h.svc.Token(ctx, url.Values{"grant_type": {mcpoauthdom.DeviceGrantType}, "device_code": {"not-a-device-code"}, "client_id": {mcpoauthdom.DeviceClientID}}, "", mcpoauth.Actor{})
	wantOAuth(t, oerr, "invalid_request")
	_, oerr = h.exchange(resp.DeviceCode, verifier, nil)
	wantOAuth(t, oerr, "invalid_grant")
}

func TestDeviceGrantRefusesUnregisteredClients(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, c := range []struct{ client, want string }{
		{clientID, "invalid_client"},      // metadata document, never stored: unknown here
		{"octc_nobody", "invalid_client"}, // unknown
		{"", "invalid_request"},           // missing
	} {
		_, oerr := h.svc.StartDeviceAuthorization(ctx, url.Values{"client_id": {c.client}}, mcpoauth.Actor{})
		wantOAuth(t, oerr, c.want)
	}
	// A stored metadata-document client (approved once through the browser)
	// still may not use the device grant: its name rests on redirect URIs.
	user := h.member(h.tenant, "member", "findings:read")
	h.approve(user, h.tenant, authorizeQuery(nil))
	_, oerr := h.svc.StartDeviceAuthorization(ctx, url.Values{"client_id": {clientID}}, mcpoauth.Actor{})
	wantOAuth(t, oerr, "unauthorized_client")
	for _, f := range []url.Values{
		{"client_id": {mcpoauthdom.DeviceClientID}, "resource": {"https://elsewhere.example/api/v1/mcp"}},
		{"client_id": {mcpoauthdom.DeviceClientID}, "scope": {"mcp:everything"}},
		{"client_id": {mcpoauthdom.DeviceClientID, mcpoauthdom.DeviceClientID}},
	} {
		if _, oerr := h.svc.StartDeviceAuthorization(ctx, f, mcpoauth.Actor{}); oerr == nil {
			t.Fatalf("accepted %v", f)
		}
	}
}

func TestDeviceFlowOrganizationClientIsTenantBound(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner := h.member(h.tenant, "owner")
	c, err := h.svc.CreateOrganizationClient(ctx, shared.MustIDFromString(h.tenant), owner, "CI runner", []string{"http://127.0.0.1/cb"}, mcpoauth.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	// A member of the other organization enters the code in their own
	// organization: the client is not theirs.
	other := h.member(h.other, "member", "findings:read")
	resp := h.startDevice(c.ClientID, "203.0.113.12")
	otherTenant := shared.MustIDFromString(h.other)
	id, err := h.svc.EnterUserCode(ctx, resp.UserCode, other, otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	view, err := h.svc.ConsentRequest(ctx, id, other, otherTenant)
	if err != nil || view.Blocked != mcpoauth.BlockedClientNotFound {
		t.Fatalf("other organization's client not blocked: %+v %v", view, err)
	}
	if _, err := h.svc.Approve(ctx, id, other, otherTenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrPolicy) {
		t.Fatalf("approved another organization's client: %v", err)
	}
	// In its own organization it works.
	member := h.member(h.tenant, "member", "findings:read")
	resp = h.startDevice(c.ClientID, "203.0.113.13")
	id, err = h.svc.EnterUserCode(ctx, resp.UserCode, member, shared.MustIDFromString(h.tenant))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, id, member, shared.MustIDFromString(h.tenant), mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if _, oerr := h.poll(resp.DeviceCode, c.ClientID); oerr != nil {
		t.Fatalf("poll: %v", oerr)
	}
}

func TestDeviceApprovalNeedsMembershipAndNoFullData(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	// The person enters the code while their session is in an organization
	// they are not a member of: nothing is granted.
	outsider := h.member(h.other, "member", "findings:read")
	resp := h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.14")
	id, err := h.svc.EnterUserCode(ctx, resp.UserCode, outsider, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, id, outsider, tenant, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrConsentUnavailable) {
		t.Fatalf("non-member approved: %v", err)
	}
	// An owner may not hand a terminal access to all organization data.
	owner := h.member(h.tenant, "owner")
	resp = h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.15")
	id, err = h.svc.EnterUserCode(ctx, resp.UserCode, owner, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ApproveAccess(ctx, id, owner, tenant, true, mcpoauth.Actor{}); !errors.Is(err, mcpoauth.ErrDeviceFullData) {
		t.Fatalf("full data approved for a terminal: %v", err)
	}
}

func TestDeviceFlowPolicySwitch(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	user := h.member(h.tenant, "member", "findings:read")

	h.policies[h.tenant] = tenantdom.MCPSettings{DeviceFlowDisabled: true}
	resp := h.startDevice(mcpoauthdom.DeviceClientID, "203.0.113.16")
	if _, err := h.svc.EnterUserCode(ctx, resp.UserCode, user, tenant); !errors.Is(err, mcpoauth.ErrDeviceFlowDisabled) {
		t.Fatalf("code accepted with the flow off: %v", err)
	}

	// On: a terminal connects. Off again: its tokens stop working and its
	// refresh token is refused; browser connections are untouched.
	delete(h.policies, h.tenant)
	id, err := h.svc.EnterUserCode(ctx, resp.UserCode, user, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, id, user, tenant, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	tok, oerr := h.poll(resp.DeviceCode, mcpoauthdom.DeviceClientID)
	if oerr != nil {
		t.Fatal(oerr)
	}
	browser, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	h.policies[h.tenant] = tenantdom.MCPSettings{DeviceFlowDisabled: true}
	if _, err := h.principal(tok.AccessToken); !errors.Is(err, mcpoauth.ErrInvalidToken) {
		t.Fatalf("terminal token works with the flow off: %v", err)
	}
	if _, oerr := h.svc.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {mcpoauthdom.DeviceClientID}}, "", mcpoauth.Actor{}); oerr == nil {
		t.Fatal("terminal refresh works with the flow off")
	}
	if _, err := h.principal(browser.AccessToken); err != nil {
		t.Fatalf("browser connection stopped by the device switch: %v", err)
	}
}
