package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/user"
	emaildom "github.com/openctemio/openctem/server/pkg/email"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeUsers struct {
	byEmail map[string]*user.User
	byID    map[string]*user.User
	err     error
}

func (f *fakeUsers) GetByEmail(_ context.Context, e string) (*user.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byEmail[strings.ToLower(e)]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeUsers) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byID[id.String()]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}

type fakeTenants struct {
	mu    sync.Mutex
	byID  map[string]*tenant.Tenant
	asked []string
	err   error
}

func (f *fakeTenants) GetByID(_ context.Context, id shared.ID) (*tenant.Tenant, error) {
	f.mu.Lock()
	f.asked = append(f.asked, id.String())
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if t, ok := f.byID[id.String()]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

func mkUser(t *testing.T, email, lang string) *user.User {
	t.Helper()
	u, err := user.New(email, "Linh")
	if err != nil {
		t.Fatal(err)
	}
	u.UpdatePreferences(user.Preferences{Language: lang})
	return u
}

func mkTenant(t *testing.T, slug, lang string) *tenant.Tenant {
	t.Helper()
	tn, err := tenant.NewTenant("Org "+slug, slug, "creator")
	if err != nil {
		t.Fatal(err)
	}
	g := tenant.GeneralSettings{Language: lang}
	if err := tn.UpdateGeneralSettings(g); err != nil {
		t.Fatal(err)
	}
	return tn
}

func TestLocaleResolverPrecedence(t *testing.T) {
	viUser := mkUser(t, "vi@example.com", "vi")
	enUser := mkUser(t, "en@example.com", "en")
	noLang := mkUser(t, "none@example.com", "")
	jaUser := mkUser(t, "ja@example.com", "ja")
	viOrg := mkTenant(t, "vi-org", "vi")
	enOrg := mkTenant(t, "en-org", "en")
	jaOrg := mkTenant(t, "ja-org", "ja")

	users := &fakeUsers{
		byEmail: map[string]*user.User{"vi@example.com": viUser, "en@example.com": enUser, "none@example.com": noLang, "ja@example.com": jaUser},
		byID:    map[string]*user.User{viUser.ID().String(): viUser, enUser.ID().String(): enUser},
	}
	tenants := &fakeTenants{byID: map[string]*tenant.Tenant{viOrg.ID().String(): viOrg, enOrg.ID().String(): enOrg, jaOrg.ID().String(): jaOrg}}
	r := NewRepoEmailLocaleResolver(users, tenants, logger.NewNop())
	ctx := context.Background()

	cases := []struct {
		name, email, tenant, want string
	}{
		{"user vi beats org en", "vi@example.com", enOrg.ID().String(), "vi"},
		{"user en beats org vi", "en@example.com", viOrg.ID().String(), "en"},
		{"user without language uses org", "none@example.com", viOrg.ID().String(), "vi"},
		{"no account uses org", "stranger@example.com", viOrg.ID().String(), "vi"},
		{"no account no org is en", "stranger@example.com", "", "en"},
		{"unknown user language falls to org", "ja@example.com", viOrg.ID().String(), "vi"},
		{"unknown org language is en", "stranger@example.com", jaOrg.ID().String(), "en"},
		{"unknown user and org is en", "ja@example.com", jaOrg.ID().String(), "en"},
		{"malformed tenant id is en", "stranger@example.com", "not-a-uuid", "en"},
		{"address case does not matter", "VI@Example.com", "", "vi"},
	}
	for _, c := range cases {
		if got := r.LocaleForEmail(ctx, c.email, c.tenant); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := r.LocaleForUser(ctx, viUser.ID().String(), enOrg.ID().String()); got != "vi" {
		t.Errorf("by id: got %q", got)
	}
	if got := r.LocaleForUser(ctx, "not-a-uuid", viOrg.ID().String()); got != "vi" {
		t.Errorf("bad user id falls to org: got %q", got)
	}
	if got := r.LocaleForUser(ctx, shared.NewID().String(), ""); got != "en" {
		t.Errorf("unknown user id: got %q", got)
	}
}

// The organization default is read only for the tenant the e-mail is for, and
// not at all when the account has its own language.
func TestLocaleResolverIsTenantScoped(t *testing.T) {
	viUser := mkUser(t, "vi@example.com", "vi")
	orgA := mkTenant(t, "org-a", "vi")
	orgB := mkTenant(t, "org-b", "en")
	users := &fakeUsers{byEmail: map[string]*user.User{"vi@example.com": viUser}}
	tenants := &fakeTenants{byID: map[string]*tenant.Tenant{orgA.ID().String(): orgA, orgB.ID().String(): orgB}}
	r := NewRepoEmailLocaleResolver(users, tenants, logger.NewNop())

	_ = r.LocaleForEmail(context.Background(), "vi@example.com", orgA.ID().String())
	if len(tenants.asked) != 0 {
		t.Fatalf("org read although the account has a language: %v", tenants.asked)
	}
	_ = r.LocaleForEmail(context.Background(), "stranger@example.com", orgA.ID().String())
	_ = r.LocaleForEmail(context.Background(), "stranger@example.com", "")
	if len(tenants.asked) != 1 || tenants.asked[0] != orgA.ID().String() {
		t.Fatalf("tenants read = %v, want only org A once", tenants.asked)
	}
}

func TestLocaleResolverLookupErrorsFallBackToEnglish(t *testing.T) {
	boom := errors.New("db down")
	viOrg := mkTenant(t, "vi-org", "vi")
	users := &fakeUsers{err: boom}
	tenants := &fakeTenants{err: boom, byID: map[string]*tenant.Tenant{viOrg.ID().String(): viOrg}}
	r := NewRepoEmailLocaleResolver(users, tenants, logger.NewNop())
	if got := r.LocaleForEmail(context.Background(), "a@example.com", viOrg.ID().String()); got != "en" {
		t.Fatalf("both lookups failing: got %q", got)
	}
	if got := r.LocaleForUser(context.Background(), shared.NewID().String(), viOrg.ID().String()); got != "en" {
		t.Fatalf("both lookups failing by id: got %q", got)
	}
	// Only the user lookup failing still uses the organization default.
	tenants.err = nil
	if got := r.LocaleForEmail(context.Background(), "a@example.com", viOrg.ID().String()); got != "vi" {
		t.Fatalf("user lookup failing, org ok: got %q", got)
	}
	// No repositories at all.
	if got := NewRepoEmailLocaleResolver(nil, nil, logger.NewNop()).LocaleForEmail(context.Background(), "a@example.com", "x"); got != "en" {
		t.Fatalf("nil repos: got %q", got)
	}
}

// ---- the service renders in the recipient's language ----

type capSender struct {
	mu    sync.Mutex
	tmpl  emaildom.Template
	data  any
	msg   *emaildom.Message
	calls int
}

func (c *capSender) IsConfigured() bool { return true }
func (c *capSender) Send(_ context.Context, m *emaildom.Message) error {
	c.mu.Lock()
	c.msg = m
	c.calls++
	c.mu.Unlock()
	return nil
}
func (c *capSender) SendTemplate(_ context.Context, _ string, t emaildom.Template, d any) error {
	c.mu.Lock()
	c.tmpl, c.data = t, d
	c.calls++
	c.mu.Unlock()
	return nil
}

func renderCaptured(t *testing.T, c *capSender) (string, string) {
	t.Helper()
	subject, body, err := emaildom.NewTemplateEngine().Render(c.tmpl, c.data)
	if err != nil {
		t.Fatal(err)
	}
	return subject, body
}

func newLocaleService(sender *capSender, r EmailLocaleResolver) *EmailService {
	s := NewEmailService(sender, config.SMTPConfig{BaseURL: "https://app.example.com"}, "App", logger.NewNop())
	if r != nil {
		s.SetLocaleResolver(r)
	}
	return s
}

func repoResolver(t *testing.T) (*RepoEmailLocaleResolver, *tenant.Tenant) {
	viUser := mkUser(t, "vi@example.com", "vi")
	viOrg := mkTenant(t, "vi-org", "vi")
	return NewRepoEmailLocaleResolver(
		&fakeUsers{byEmail: map[string]*user.User{"vi@example.com": viUser}},
		&fakeTenants{byID: map[string]*tenant.Tenant{viOrg.ID().String(): viOrg}},
		logger.NewNop()), viOrg
}

func TestServiceSendsVietnameseToVietnameseRecipient(t *testing.T) {
	r, _ := repoResolver(t)
	c := &capSender{}
	s := newLocaleService(c, r)

	if err := s.SendVerificationEmail(context.Background(), "vi@example.com", "Linh", "tok", 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	subject, body := renderCaptured(t, c)
	if subject != "Xác minh địa chỉ email của bạn" {
		t.Fatalf("subject = %q", subject)
	}
	if !strings.Contains(body, "2 ngày") || !strings.Contains(body, `lang="vi"`) {
		t.Fatalf("body is not Vietnamese: %.200s", body)
	}

	// A recipient with no account and no organization gets English.
	if err := s.SendVerificationEmail(context.Background(), "new@example.com", "Sam", "tok", 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	subject, body = renderCaptured(t, c)
	if subject != "Verify your email address" || !strings.Contains(body, "2 days") {
		t.Fatalf("english expected: %q", subject)
	}
}

func TestServiceUsesOrganizationDefaultForUnknownRecipient(t *testing.T) {
	r, org := repoResolver(t)
	c := &capSender{}
	s := newLocaleService(c, r)
	if err := s.SendTeamInvitationEmail(context.Background(), "invitee@example.com", "Inviter", "Acme", "tok", time.Hour, org.ID().String()); err != nil {
		t.Fatal(err)
	}
	subject, _ := renderCaptured(t, c)
	if subject != "Bạn được mời tham gia Acme" {
		t.Fatalf("subject = %q", subject)
	}
	// The same e-mail with no organization context stays English.
	if err := s.SendTeamInvitationEmail(context.Background(), "invitee@example.com", "Inviter", "Acme", "tok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if subject, _ = renderCaptured(t, c); subject != "You've been invited to join Acme" {
		t.Fatalf("subject = %q", subject)
	}
}

type panicLocale struct{}

func (panicLocale) LocaleForEmail(context.Context, string, string) string { return "klingon" }
func (panicLocale) LocaleForUser(context.Context, string, string) string  { return "" }

func TestServiceFallsBackToEnglishWithoutResolverOrOnBadAnswer(t *testing.T) {
	for name, r := range map[string]EmailLocaleResolver{"none": nil, "unsupported": panicLocale{}} {
		c := &capSender{}
		s := newLocaleService(c, r)
		if err := s.SendWelcomeEmail(context.Background(), "vi@example.com", "Linh"); err != nil {
			t.Fatal(err)
		}
		if subject, _ := renderCaptured(t, c); subject != "Welcome to App" {
			t.Errorf("%s: subject = %q", name, subject)
		}
	}
	// A failing lookup must not block the send.
	c := &capSender{}
	s := newLocaleService(c, NewRepoEmailLocaleResolver(&fakeUsers{err: errors.New("down")}, &fakeTenants{err: errors.New("down")}, logger.NewNop()))
	if err := s.SendPasswordChangedEmail(context.Background(), "vi@example.com", "Linh", "1.1.1.1"); err != nil || c.calls != 1 {
		t.Fatalf("send blocked by lookup failure: err=%v calls=%d", err, c.calls)
	}
}

func TestInlineAndSecurityNoticesAreLocalized(t *testing.T) {
	r, _ := repoResolver(t)
	c := &capSender{}
	s := newLocaleService(c, r)

	if err := s.SendDomainManagedEmail(context.Background(), "vi@example.com", `ex<b>.com`); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.msg.Subject, "[App] Các tài khoản trên ") || strings.Contains(c.msg.Body, "<b>") {
		t.Fatalf("domain managed: %q / %q", c.msg.Subject, c.msg.Body)
	}

	s.NotifyMFADisabled(context.Background(), "vi@example.com", "Linh", "1.1.1.1")
	waitFor(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.tmpl == emaildom.TemplateSecurityNotice })
	c.mu.Lock()
	n := c.data.(emaildom.SecurityNoticeData)
	c.mu.Unlock()
	if n.Subject != "Xác thực hai yếu tố đã bị tắt" || n.LocaleCode() != "vi" {
		t.Fatalf("notice = %+v", n)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}
