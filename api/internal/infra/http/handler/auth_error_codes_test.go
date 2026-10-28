package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Every refusal in the table has its own code, is a client error (the one 503
// is the server's own "feature not installed"), and says nothing the owner's
// text rules forbid.
func TestAuthErrorTable_DistinctCodesNone500(t *testing.T) {
	seen := map[string]int{}
	for i, en := range authErrorTable {
		if len(en.Errs) == 0 || en.Code == "" || en.Message == "" {
			t.Fatalf("entry %d is incomplete: %+v", i, en)
		}
		if prev, dup := seen[string(en.Code)]; dup {
			t.Errorf("code %s is used by entries %d and %d", en.Code, prev, i)
		}
		seen[string(en.Code)] = i
		if en.Status == http.StatusInternalServerError || en.Status < 400 {
			t.Errorf("%s answers %d", en.Code, en.Status)
		}
		if en.Status >= 500 && en.Status != http.StatusServiceUnavailable {
			t.Errorf("%s answers %d", en.Code, en.Status)
		}
		for _, bad := range []string{"—", "–", " · ", "team", "Team", "Please"} {
			if strings.Contains(en.Message, bad) {
				t.Errorf("%s message %q contains %q", en.Code, en.Message, bad)
			}
		}
	}
}

// Each sentinel reaches its own entry, also when a service wraps it, and no
// earlier entry shadows it.
func TestAuthErrorTable_EverySentinelResolvesToItsEntry(t *testing.T) {
	for _, en := range authErrorTable {
		for _, target := range en.Errs {
			got, ok := lookupAuthError(fmt.Errorf("while signing in: %w", target))
			if !ok || got.Code != en.Code {
				t.Errorf("%v resolved to %q (found=%v), want %q", target, got.Code, ok, en.Code)
			}
			rec := httptest.NewRecorder()
			(&LocalAuthHandler{logger: logger.NewNop()}).handleAuthError(rec, target)
			if rec.Code != en.Status {
				t.Errorf("%v: handler answered %d, want %d", target, rec.Code, en.Status)
			}
			var body struct{ Code string }
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body.Code != string(en.Code) {
				t.Errorf("%v: body code %q, want %q", target, body.Code, en.Code)
			}
		}
	}
}

// The federated handlers answer the same codes as the local one, and a refusal
// that used to be a 500 (no case) is now a 4xx.
func TestFederatedHandlersUseTheTable(t *testing.T) {
	sso := &SSOHandler{logger: logger.NewNop()}
	oauth := &OAuthHandler{logger: logger.NewNop()}
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"different method":    {auth.ErrSSODifferentMethod, "SSO_DIFFERENT_METHOD"},
		"domain":              {auth.ErrSSODomainNotAllowed, "SSO_DOMAIN_NOT_ALLOWED"},
		"federated domain":    {auth.ErrSSOFederatedDomainUnverified, "SSO_DOMAIN_NOT_ALLOWED"},
		"awaiting":            {auth.ErrSSOAwaitingApproval, "SSO_AWAITING_APPROVAL"},
		"not a member":        {auth.ErrSSONotAMember, "SSO_NOT_A_MEMBER"},
		"federated member":    {auth.ErrSSOFederatedNotMember, "SSO_NOT_A_MEMBER"},
		"link":                {auth.ErrAccountLinkRequiresVerification, "ACCOUNT_LINK_REQUIRED"},
		"takeover":            {auth.ErrSSOFederatedTakeover, "ACCOUNT_LINK_REQUIRED"},
		"console":             {auth.ErrUseAdminConsole, "USE_ADMIN_CONSOLE"},
		"unverified at idp":   {auth.ErrEmailUnverifiedAtIDP, "EMAIL_UNVERIFIED_AT_IDP"},
		"invalid id token":    {auth.ErrSSOInvalidIDToken, "SSO_INVALID_ID_TOKEN"},
		"no email":            {auth.ErrSSONoEmail, "SSO_NO_EMAIL"},
		"registration closed": {auth.ErrSSORegistrationDisabled, "SSO_REGISTRATION_DISABLED"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, serve := range []func(http.ResponseWriter, error){sso.handlePublicError, oauth.handleOAuthError} {
				rec := httptest.NewRecorder()
				serve(rec, fmt.Errorf("wrapped: %w", tc.err))
				if rec.Code >= 500 {
					t.Fatalf("answered %d", rec.Code)
				}
				if !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) {
					t.Fatalf("body %s lacks code %s", rec.Body.String(), tc.code)
				}
			}
		})
	}
}

// A different sign-in method is its own refusal: it must no longer read as a
// domain refusal.
func TestDifferentMethodIsNotADomainRefusal(t *testing.T) {
	if errors.Is(auth.ErrSSODifferentMethod, auth.ErrSSODomainNotAllowed) {
		t.Fatal("different method must not unwrap to domain not allowed")
	}
}

// The invitation sentinels are validation errors for other callers and carry
// their own code here.
func TestInvitationSentinelsHaveCodes(t *testing.T) {
	for sentinel, code := range map[error]string{
		tenantapp.ErrInvitationAlreadyMember:       "INVITATION_ALREADY_MEMBER",
		tenantapp.ErrInvitationMembershipSuspended: "INVITATION_MEMBERSHIP_SUSPENDED",
		tenantapp.ErrMembershipSuspendedReactivate: "MEMBERSHIP_SUSPENDED_REACTIVATE",
	} {
		if !errors.Is(sentinel, shared.ErrValidation) {
			t.Errorf("%v must stay a validation error", sentinel)
		}
		rec := httptest.NewRecorder()
		(&TenantHandler{logger: logger.NewNop()}).handleServiceError(rec, sentinel)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%v: %d %s", sentinel, rec.Code, rec.Body.String())
		}
	}
}

// The SAML redirect carries a code from the fixed list, never free text, and
// stays generic for an error it does not know.
func TestSAMLRedirectCarriesACode(t *testing.T) {
	h := &SAMLHandler{logger: logger.NewNop(), frontendURL: "https://app.example.test"}
	for err, want := range map[error]string{
		auth.ErrSSOAwaitingApproval:     "awaiting_approval",
		auth.ErrSSOFederatedNotMember:   "not_member",
		auth.ErrSSODomainNotAllowed:     "domain_not_allowed",
		auth.ErrSSOFederatedTakeover:    "link_required",
		auth.ErrUseAdminConsole:         "use_console",
		errors.New("assertion expired"): "saml_failed",
	} {
		rec := httptest.NewRecorder()
		h.redirectWithError(rec, httptest.NewRequest(http.MethodPost, "/acs", nil), err)
		loc, perr := url.Parse(rec.Header().Get("Location"))
		if perr != nil || loc.Path != "/login" || loc.Query().Get("error") != want {
			t.Errorf("%v: redirected to %s, want error=%s", err, rec.Header().Get("Location"), want)
		}
	}
}

// /auth/info reports no email-verification field: the configured flag is not
// the rule that applies to a person (organizations can tighten it).
func TestAuthInfoHasNoVerificationField(t *testing.T) {
	b, err := json.Marshal(AuthInfoResponse{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "verification") {
		t.Fatalf("auth info still carries a verification field: %s", b)
	}
}
