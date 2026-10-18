package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// adminWriteClass says how one console write is confirmed.
type adminWriteClass string

const (
	// stepUpRoute: the route-level step-up (RequireAdminStepUp).
	stepUpRoute adminWriteClass = "step-up"
	// routine: an operational write that changes no identity, privilege or
	// platform trust. Role-gated and audited; the reason says why no step-up.
	routine adminWriteClass = "routine"
	// signIn: the console's own sign-in steps (no session yet).
	signIn adminWriteClass = "sign-in"
)

// adminWriteInventory classifies every state-changing console route. A new
// admin write route fails TestAdminWriteRoutesClassified until it is listed
// here; every identity, privilege or platform-trust change must be
// stepUpRoute.
var adminWriteInventory = map[string]struct {
	class adminWriteClass
	why   string
}{
	// Sign-in steps: before a console session exists.
	"POST /api/v1/admin/auth/login":                    {signIn, "first step of the console sign-in"},
	"POST /api/v1/admin/auth/mfa":                      {signIn, "the TOTP step of the sign-in"},
	"POST /api/v1/admin/auth/logout":                   {signIn, "ends the caller's own session"},
	"POST /api/v1/admin/auth/password":                 {signIn, "needs the current password"},
	"POST /api/v1/admin/auth/elevate":                  {stepUpRoute, "elevates the session's role"},
	"DELETE /api/v1/admin/auth/elevate":                {routine, "drops the session back to read-only"},
	"POST /api/v1/admin/auth/idp/start":                {signIn, "platform identity provider sign-in"},
	"POST /api/v1/admin/auth/idp/callback":             {signIn, "platform identity provider sign-in"},
	"POST /api/v1/admin/auth/webauthn/session/options": {signIn, "the security-key step of the sign-in"},
	"POST /api/v1/admin/auth/webauthn/session":         {signIn, "the security-key step of the sign-in"},
	"POST /api/v1/admin/auth/recovery":                 {signIn, "the recovery-code step of the sign-in"},
	"POST /api/v1/admin/auth/step-up/webauthn/options": {signIn, "opens a step-up assertion for the caller's own session"},
	"POST /api/v1/admin/auth/step-up/webauthn":         {signIn, "is the step-up itself (security key)"},

	// The caller's own console factors.
	"POST /api/v1/admin/auth/webauthn/credentials/options": {stepUpRoute, "adds a sign-in factor"},
	"POST /api/v1/admin/auth/webauthn/credentials":         {routine, "completes the ceremony its step-up options call opened in this session (single use)"},
	"PATCH /api/v1/admin/auth/webauthn/credentials/{id}":   {routine, "renames the caller's own key; audited"},
	"DELETE /api/v1/admin/auth/webauthn/credentials/{id}":  {stepUpRoute, "removes a sign-in factor"},
	"POST /api/v1/admin/auth/recovery-codes":               {stepUpRoute, "replaces the caller's recovery codes"},
	"PUT /api/v1/admin/settings/console-mfa/":              {stepUpRoute, "who may sign in to the console, and how"},

	// Support access: opening a support session reads an organization's data
	// under its grant; ending one only reduces access.
	"POST /api/v1/admin/support/grants/{grant_id}/sessions": {stepUpRoute, "opens read access to an organization's data (its grant)"},
	"DELETE /api/v1/admin/support/sessions/{session_id}":    {routine, "ends the caller's own support session; audited in both logs"},

	// Identity and privilege of administrators.
	"POST /api/v1/admin/administrators/":                         {stepUpRoute, "creates an administrator"},
	"PATCH /api/v1/admin/users/{id}":                             {stepUpRoute, "changes an administrator's role or state"},
	"DELETE /api/v1/admin/users/{id}":                            {stepUpRoute, "deletes an administrator"},
	"POST /api/v1/admin/users/{id}/reset-credentials":            {stepUpRoute, "resets an administrator's sign-in"},
	"POST /api/v1/admin/users/{id}/break-glass-test":             {stepUpRoute, "records a break-glass test"},
	"DELETE /api/v1/admin/users/{id}/idp-binding":                {stepUpRoute, "unbinds an administrator from the identity provider"},
	"PUT /api/v1/admin/platform-idp/":                            {stepUpRoute, "who may sign in to the console"},
	"DELETE /api/v1/admin/platform-idp/":                         {stepUpRoute, "who may sign in to the console"},
	"DELETE /api/v1/admin/console-sessions/{console_session_id}": {stepUpRoute, "ends an administrator's session"},

	// Organizations: creation, owners, sign-in trust.
	"POST /api/v1/admin/tenants/":                                            {stepUpRoute, "creates an organization"},
	"POST /api/v1/admin/access-requests/{id}/approve":                        {stepUpRoute, "creates an organization and its owner"},
	"POST /api/v1/admin/tenants/{tenantId}/users":                            {stepUpRoute, "creates or recovers an organization owner"},
	"PUT /api/v1/admin/tenants/{tenantId}/sso/enforcement":                   {stepUpRoute, "organization sign-in trust"},
	"PUT /api/v1/admin/tenants/{tenantId}/sso/saml":                          {stepUpRoute, "organization sign-in trust"},
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/saml":                       {stepUpRoute, "organization sign-in trust"},
	"POST /api/v1/admin/tenants/{tenantId}/sso/identity-providers":           {stepUpRoute, "organization sign-in trust"},
	"PUT /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":       {stepUpRoute, "organization sign-in trust"},
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/identity-providers/{id}":    {stepUpRoute, "organization sign-in trust"},
	"POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains":             {stepUpRoute, "organization sign-in trust"},
	"POST /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}/verify": {stepUpRoute, "organization sign-in trust"},
	"DELETE /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}":      {stepUpRoute, "organization sign-in trust"},
	"PATCH /api/v1/admin/tenants/{tenantId}/sso/verified-domains/{id}":       {stepUpRoute, "organization sign-in trust (JIT)"},
	"POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline":           {stepUpRoute, "re-signs an organization's audit chain"},
	"PUT /api/v1/admin/tenants/{tenantId}/scan-approval-policy":              {stepUpRoute, "scan governance of an organization"},
	"PUT /api/v1/admin/tenants/{tenantId}/shared-sensors":                    {stepUpRoute, "whether an organization's scans may run on shared sensors"},
	"PUT /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny":          {stepUpRoute, "module entitlement"},
	"POST /api/v1/admin/tenants/{tenantId}/suspend":                          {stepUpRoute, "cuts every credential of the organization; reason, critical audit"},
	"POST /api/v1/admin/tenants/{tenantId}/unsuspend":                        {stepUpRoute, "restores every credential of the organization; reason, critical audit"},
	"DELETE /api/v1/admin/tenants/{tenantId}/modules/{module_id}/deny":       {stepUpRoute, "module entitlement"},
	"PUT /api/v1/admin/tenants/{tenantId}/limits/{key}":                      {stepUpRoute, "a limit of 0 freezes the organization"},
	"DELETE /api/v1/admin/tenants/{tenantId}/limits/{key}":                   {stepUpRoute, "removing a limit lifts an abuse control"},
	"PUT /api/v1/admin/tenants/{tenantId}/idle/policy":                       {stepUpRoute, "can put an organization in read-only mode"},
	"POST /api/v1/admin/access-requests/{id}/reject":                         {routine, "refuses a request; nothing is created"},

	// Platform settings and trust.
	"PUT /api/v1/admin/settings/signup/":                            {stepUpRoute, "sign-up mode"},
	"PUT /api/v1/admin/settings/email/":                             {stepUpRoute, "platform mail relay"},
	"POST /api/v1/admin/settings/email/test":                        {routine, "sends a test to the caller's own address"},
	"PUT /api/v1/admin/settings/legal/":                             {stepUpRoute, "legal pages"},
	"PUT /api/v1/admin/settings/limits/":                            {stepUpRoute, "self-service default limits"},
	"PUT /api/v1/admin/settings/scan-approval-policy/":              {stepUpRoute, "scan governance default"},
	"PUT /api/v1/admin/settings/platform-sensor-proof/":             {stepUpRoute, "platform sensor domain proof"},
	"POST /api/v1/admin/instance-scan-zones/":                       {stepUpRoute, "an instance scan zone that lets shared sensors reach private ranges"},
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}":               {stepUpRoute, "the ranges of an instance scan zone"},
	"DELETE /api/v1/admin/instance-scan-zones/{zone_id}":            {stepUpRoute, "an instance scan zone"},
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}/sensors":       {stepUpRoute, "the shared sensors that serve an instance scan zone"},
	"PUT /api/v1/admin/instance-scan-zones/{zone_id}/organizations": {stepUpRoute, "the organizations an instance scan zone is assigned to"},
	"PUT /api/v1/admin/settings/shared-sensors/":                    {stepUpRoute, "shared sensors on or off for the instance, and the default for organizations"},
	"POST /api/v1/admin/shared-sensors/{sensor_id}/disable":         {stepUpRoute, "stops a shared sensor taking jobs"},
	"POST /api/v1/admin/shared-sensors/{sensor_id}/enable":          {stepUpRoute, "lets a shared sensor take every organization's jobs again"},
	"POST /api/v1/admin/shared-sensors/{sensor_id}/revoke":          {stepUpRoute, "revokes a shared sensor for good"},
	"POST /api/v1/admin/shared-sensors/jobs/{job_id}/view":          {routine, "reads a job's targets and logs; changes nothing; reason required, ops_admin+, rate-limited, audited high before data is returned"},
	"PUT /api/v1/admin/settings/shared-sensor-internal-zones/":      {stepUpRoute, "whether shared sensors may scan internal zones"},
	"PUT /api/v1/admin/settings/shared-sensor-anomaly/":             {stepUpRoute, "shared sensor anomaly alert thresholds"},
	"PUT /api/v1/admin/settings/shared-sensors/egress":              {stepUpRoute, "egress addresses every organization is told to allowlist"},
	"PUT /api/v1/admin/program-feed/local-bundle":                   {stepUpRoute, "program feed source"},
	"POST /api/v1/admin/shared-sensors/enrollment-tokens":           {stepUpRoute, "shared sensor enrollment token"},
	"POST /api/v1/admin/version-check/import":                       {stepUpRoute, "release feed trust: what the console says about releases"},
	"PUT /api/v1/admin/version-check/enabled":                       {stepUpRoute, "egress and privacy: the daily outbound check"},
	"POST /api/v1/admin/content-packs/":                             {stepUpRoute, "platform content pack"},
	"POST /api/v1/admin/content-packs/import":                       {stepUpRoute, "platform content pack"},
	"POST /api/v1/admin/content-packs/{id}/revoke":                  {stepUpRoute, "platform content pack"},
	"PUT /api/v1/admin/content-packs/channels/{channel}":            {stepUpRoute, "platform content pack"},
	"POST /api/v1/admin/content-catalog/import":                     {stepUpRoute, "content catalog bundle import"},
	"POST /api/v1/admin/content-catalog/packages":                   {stepUpRoute, "instance content package"},
	"POST /api/v1/admin/content-catalog/packages/revoke":            {stepUpRoute, "instance content package"},
	"POST /api/v1/admin/announcements/":                             {stepUpRoute, "a banner every user sees (phishing channel in a hijacked session)"},
	"POST /api/v1/admin/announcements/{announcement_id}/cancel":     {stepUpRoute, "ends a banner (can hide a maintenance or incident notice)"},
	"POST /api/v1/admin/threat-intel/sync":                          {routine, "runs a public feed sync; audited"},
	"PATCH /api/v1/admin/threat-intel/sync/{source}":                {stepUpRoute, "turning a feed off changes every organization's prioritization"},
	"POST /api/v1/admin/mcp-clients/{id}/block":                     {stepUpRoute, "cuts every organization off an AI client"},
	"POST /api/v1/admin/mcp-clients/{id}/unblock":                   {stepUpRoute, "readmits an AI client that was cut off"},
	"POST /api/v1/admin/target-mappings/":                           {routine, "scanner target mapping; rate-limited, audited"},
	"PATCH /api/v1/admin/target-mappings/{id}":                      {routine, "scanner target mapping; rate-limited, audited"},
	"DELETE /api/v1/admin/target-mappings/{id}":                     {routine, "scanner target mapping; rate-limited, audited"},

	// Account support actions: they change a person's sign-in state, so
	// step-up as well as reason, rate limit and audit.
	"POST /api/v1/admin/platform-users/{user_id}/revoke-sessions":     {stepUpRoute, "ends a user's sessions; reason, audited"},
	"POST /api/v1/admin/platform-users/{user_id}/block":               {stepUpRoute, "blocks an account everywhere; reason, critical audit"},
	"POST /api/v1/admin/platform-users/{user_id}/unblock":             {stepUpRoute, "lifts an account block; reason, critical audit"},
	"POST /api/v1/admin/platform-users/{user_id}/unlock":              {stepUpRoute, "clears a lockout; reason, audited"},
	"POST /api/v1/admin/platform-users/{user_id}/password-reset":      {stepUpRoute, "emails the user a reset link; reason, audited"},
	"POST /api/v1/admin/platform-users/{user_id}/verification-emails": {stepUpRoute, "re-sends verification; reason, audited"},
}

// inventorySessions authenticates every request as one verified super admin.
type inventorySessions struct{ a *admin.AdminUser }

func (s inventorySessions) Authenticate(context.Context, string) (*admin.AdminUser, error) {
	return s.a, nil
}

func (s inventorySessions) AuthenticateSession(context.Context, string) (*admin.AdminUser, *admin.Session, error) {
	now := time.Now()
	return s.a, &admin.Session{ID: shared.NewID(), AdminID: s.a.ID(), MFAVerified: true, AuthMethod: admin.AuthMethodPassword,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}, nil
}

// inventoryRouter registers the admin routes with every handler present (zero
// values: the tests never reach a handler body on a step-up route) and a
// confirmer that records the purposes it is asked about and refuses.
func inventoryRouter(t *testing.T) (infrahttp.Router, *[]string) {
	t.Helper()
	return inventoryRouterWith(t, nil)
}

// inventoryRouterWith is inventoryRouter with a hook to adjust the handlers.
func inventoryRouterWith(t *testing.T, adjust func(*Handlers)) (infrahttp.Router, *[]string) {
	t.Helper()
	router, purposes, _ := inventoryRouterFull(t, adjust)
	return router, purposes
}

// inventoryRouterFresh is inventoryRouter that also reports, per purpose,
// whether the route asked for a fresh check (no step-up window).
func inventoryRouterFresh(t *testing.T) (infrahttp.Router, *[]string, map[string]bool) {
	t.Helper()
	return inventoryRouterFull(t, nil)
}

// inventoryRouterFull is the router with an optional hook to adjust the
// handlers, reporting the purposes asked and whether each asked fresh.
func inventoryRouterFull(t *testing.T, adjust func(*Handlers)) (infrahttp.Router, *[]string, map[string]bool) {
	t.Helper()
	fresh := map[string]bool{}
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "root@example.com", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	var h Handlers
	hv := reflect.ValueOf(&h).Elem()
	for i := 0; i < hv.NumField(); i++ {
		f := hv.Field(i)
		if f.Kind() == reflect.Ptr && f.Type().Elem().Kind() == reflect.Struct &&
			strings.HasSuffix(f.Type().Elem().PkgPath(), "/http/handler") {
			f.Set(reflect.New(f.Type().Elem()))
		}
	}
	h.AdminAuthMiddleware = middleware.NewAdminAuthMiddleware(inventorySessions{a}, logger.NewNop())
	purposes := &[]string{}
	h.AdminStepUp = middleware.AdminStepUpFunc(func(ctx context.Context, _ *admin.AdminUser, _ *admin.Session, code, purpose string, _ middleware.AdminStepUpClient) error {
		*purposes = append(*purposes, purpose)
		fresh[purpose] = admin.FreshStepUpRequired(ctx)
		if code != "" {
			t.Errorf("no step-up header was sent, got code %q", code)
		}
		return admin.ErrStepUpRequired
	})
	if adjust != nil {
		adjust(&h)
	}
	router := infrahttp.NewChiRouter()
	registerAdminRoutes(router, h, nil)
	return router, purposes, fresh
}

// Adding a key, replacing recovery codes, turning the factor policy and
// recovering an organization owner must not ride the step-up window.
func TestFactorRoutesDemandFreshStepUp(t *testing.T) {
	router, _, fresh := inventoryRouterFresh(t)
	handler := router.Handler()
	for _, c := range []struct{ method, path, purpose string }{
		{"POST", "/api/v1/admin/auth/webauthn/credentials/options", "webauthn.register"},
		{"POST", "/api/v1/admin/auth/recovery-codes", "recovery_codes.generate"},
		{"PUT", "/api/v1/admin/settings/console-mfa/", "settings.console_mfa"},
		{"POST", "/api/v1/admin/tenants/" + shared.NewID().String() + "/users", "organization.owner_create"},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: "s"})
		req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: "c"})
		req.Header.Set(middleware.CSRFHeaderName, middleware.AdminCSRFToken("s"))
		handler.ServeHTTP(httptest.NewRecorder(), req)
		got, asked := fresh[c.purpose]
		if !asked || !got {
			t.Errorf("%s %s (%s): fresh check asked=%v fresh=%v", c.method, c.path, c.purpose, asked, got)
		}
	}
}

func adminWrites(t *testing.T, router infrahttp.Router) []string {
	t.Helper()
	var out []string
	_ = router.Walk(func(method, path string, _ http.Handler) error {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return nil
		}
		if strings.HasPrefix(path, "/api/v1/admin") {
			out = append(out, method+" "+path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// Every console write is classified, and every listed route exists.
func TestAdminWriteRoutesClassified(t *testing.T) {
	router, _ := inventoryRouter(t)
	writes := adminWrites(t, router)
	if len(writes) < 40 {
		t.Fatalf("only %d admin writes registered: the inventory router lost routes", len(writes))
	}
	seen := map[string]bool{}
	for _, key := range writes {
		seen[key] = true
		if _, ok := adminWriteInventory[key]; !ok {
			t.Errorf("unclassified console write %q: add it to adminWriteInventory (identity, privilege or platform-trust changes take stepUp)", key)
		}
	}
	for key := range adminWriteInventory {
		if !seen[key] {
			t.Errorf("adminWriteInventory lists %q but no such route is registered", key)
		}
	}
}

// A step-up route refuses without a code before its handler runs; every other
// write never asks the route-level step-up (no double confirmation).
func TestAdminStepUpRoutesRefuseWithoutCode(t *testing.T) {
	router, purposes := inventoryRouter(t)
	handler := router.Handler()
	for _, key := range adminWrites(t, router) {
		entry, ok := adminWriteInventory[key]
		if !ok || entry.class == signIn {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		path = strings.NewReplacer(
			"{id}", shared.NewID().String(), "{tenantId}", shared.NewID().String(),
			"{user_id}", shared.NewID().String(), "{console_session_id}", shared.NewID().String(),
			"{announcement_id}", shared.NewID().String(), "{module_id}", "pentest",
			"{key}", "seats", "{channel}", "stable", "{source}", "epss",
			"{namespace}", "acme", "{name}", "words", "{version}", "1.0.0",
		).Replace(path)
		before := len(*purposes)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: "s"})
		req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: "c"})
		req.Header.Set(middleware.CSRFHeaderName, middleware.AdminCSRFToken("s"))
		func() {
			// A zero-value handler body may panic on a non-step-up route;
			// reaching it is the point, the panic is not.
			defer func() { _ = recover() }()
			handler.ServeHTTP(rec, req)
		}()
		asked := len(*purposes) > before
		switch entry.class {
		case stepUpRoute:
			if !asked {
				t.Errorf("%s: route-level step-up not applied", key)
				continue
			}
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), string(middleware.CodeAdminStepUpRequired)) {
				t.Errorf("%s: want 401 %s, got %d %s", key, middleware.CodeAdminStepUpRequired, rec.Code, rec.Body.String())
			}
		default:
			if asked {
				t.Errorf("%s (%s) asked the route-level step-up: reclassify it as step-up", key, entry.class)
			}
		}
	}
}

// Every console route, reads included, refuses a client outside the console
// networks at the route itself (RequireAdminNetwork), so a path the
// server-wide gate read differently still cannot reach a console handler.
func TestAdminRoutesRefuseOutsideNetworks(t *testing.T) {
	router, _ := inventoryRouterWith(t, func(h *Handlers) {
		h.AdminNetwork = middleware.RequireAdminNetwork([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil)
	})
	handler := router.Handler()
	n := 0
	_ = router.Walk(func(method, path string, _ http.Handler) error {
		if !strings.HasPrefix(path, "/api/v1/admin") {
			return nil
		}
		n++
		p := strings.NewReplacer("{id}", shared.NewID().String(), "{tenantId}", shared.NewID().String(),
			"{user_id}", shared.NewID().String(), "{console_session_id}", shared.NewID().String(),
			"{announcement_id}", shared.NewID().String(), "{module_id}", "pentest", "{key}", "seats",
			"{channel}", "stable", "{source}", "epss").Replace(path)
		for _, raw := range []string{p, strings.Replace(p, "/api/v1/admin", "/api/v1//admin", 1)} {
			req := httptest.NewRequest(method, raw, strings.NewReader(`{}`))
			req.RemoteAddr = "203.0.113.9:5000"
			req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: "s"})
			req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: "c"})
			req.Header.Set(middleware.CSRFHeaderName, middleware.AdminCSRFToken("s"))
			rec := httptest.NewRecorder()
			func() {
				defer func() { _ = recover() }()
				handler.ServeHTTP(rec, req)
			}()
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), string(middleware.CodeAdminNetworkNotAllowed)) {
				t.Errorf("%s %s from outside: %d %s", method, raw, rec.Code, rec.Body.String())
			}
		}
		return nil
	})
	if n < 60 {
		t.Fatalf("only %d console routes walked", n)
	}
}
