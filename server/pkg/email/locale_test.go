package email

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

var placeholderRE = regexp.MustCompile(`\{\d+\}`)

func placeholders(s string) string {
	p := placeholderRE.FindAllString(s, -1)
	sort.Strings(p)
	return strings.Join(p, ",")
}

// A key present in one locale and not the other, or with different
// placeholders, would render a half-translated or broken e-mail.
func TestCatalogLocalesHaveSameKeysAndPlaceholders(t *testing.T) {
	en, vi := catalog[LocaleEN], catalog[LocaleVI]
	for k, v := range en {
		w, ok := vi[k]
		if !ok {
			t.Errorf("key %q missing in vi", k)
			continue
		}
		if strings.TrimSpace(w) == "" {
			t.Errorf("key %q empty in vi", k)
		}
		if placeholders(v) != placeholders(w) {
			t.Errorf("key %q placeholders differ: en %q vs vi %q", k, placeholders(v), placeholders(w))
		}
	}
	for k := range vi {
		if _, ok := en[k]; !ok {
			t.Errorf("key %q missing in en", k)
		}
	}
}

// Every key a template or the engine refers to exists in every locale.
func TestTemplateKeysExistInEveryLocale(t *testing.T) {
	src, err := os.ReadFile("templates.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?:\{\{th? \.Locale|Text\(l,) "([A-Za-z0-9.]+)"`)
	m := re.FindAllStringSubmatch(string(src), -1)
	if len(m) < 50 {
		t.Fatalf("found only %d key references; the scan is broken", len(m))
	}
	for _, x := range m {
		for _, l := range []string{LocaleEN, LocaleVI} {
			if _, ok := catalog[l][x[1]]; !ok {
				t.Errorf("template key %q missing in %s", x[1], l)
			}
		}
	}
}

func TestNormalizeLocale(t *testing.T) {
	for in, want := range map[string]string{
		"": "en", "en": "en", "vi": "vi", "VI": "vi", " vi-VN ": "vi", "vi_VN": "vi",
		"ja": "en", "zh": "en", "fr": "en", "xx-yy": "en",
	} {
		if got := NormalizeLocale(in); got != want {
			t.Errorf("NormalizeLocale(%q) = %q, want %q", in, got, want)
		}
	}
}

func allSamples(locale, name string) map[Template]any {
	b := Branding{FooterText: "footer", PoweredBy: true}
	l := Lang{Locale: locale}
	return map[Template]any{
		TemplateVerifyEmail:       VerifyEmailData{UserName: name, Email: "a@b.c", VerificationURL: "https://x/v", ExpiresIn: "24 hours", AppName: "App", Branding: b, Lang: l},
		TemplatePasswordReset:     PasswordResetData{UserName: name, Email: "a@b.c", ResetURL: "https://x/r", ExpiresIn: "1 hour", AppName: "App", IPAddress: "1.2.3.4", RequestedAt: "now", Branding: b, Lang: l},
		TemplatePasswordChanged:   PasswordChangedData{UserName: name, Email: "a@b.c", ChangedAt: "now", IPAddress: "1.2.3.4", AppName: "App", Branding: b, Lang: l},
		TemplateWelcome:           WelcomeData{UserName: name, Email: "a@b.c", LoginURL: "https://x/l", AppName: "App", Branding: b, Lang: l},
		TemplateTeamInvitation:    TeamInvitationData{InviterName: name, TeamName: name + " Org", InvitationURL: "https://x/i", ExpiresIn: "7 days", AppName: "App", Branding: b, Lang: l},
		TemplateAccountSetup:      AccountSetupData{UserName: name, TeamName: name + " Org", SetupURL: "https://x/s", ExpiresIn: "1 hour", AppName: "App", Branding: b, Lang: l},
		TemplateMemberSuspended:   MemberStatusChangeData{UserName: name, TeamName: name + " Org", ActorName: name, AppURL: "https://x", AppName: "App", Branding: b, Lang: l},
		TemplateMemberReactivated: MemberStatusChangeData{UserName: name, TeamName: name + " Org", ActorName: name, AppURL: "https://x", AppName: "App", Branding: b, Lang: l},
		TemplateSecurityNotice:    SecurityNoticeData{UserName: name, Email: "a@b.c", Subject: "Subject", Message: "Message", OccurredAt: "now", IPAddress: "1.2.3.4", AppName: "App", Branding: b, Lang: l},
	}
}

var viDiacritics = regexp.MustCompile(`[ăâđêôơưĂÂĐÊÔƠƯạảãấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]`)

func TestEveryTemplateRendersInEachLocale(t *testing.T) {
	e := NewTemplateEngine()
	for _, locale := range []string{LocaleEN, LocaleVI} {
		for tmpl, data := range allSamples(locale, "Linh") {
			subject, body, err := e.Render(tmpl, data)
			if err != nil {
				t.Fatalf("%s/%s: %v", locale, tmpl, err)
			}
			if subject == "" || body == "" {
				t.Fatalf("%s/%s: empty subject or body", locale, tmpl)
			}
			if !strings.Contains(body, `<html lang="`+locale+`">`) {
				t.Errorf("%s/%s: html lang not set", locale, tmpl)
			}
			if placeholderRE.MatchString(subject + body) {
				t.Errorf("%s/%s: unfilled placeholder in output", locale, tmpl)
			}
			if strings.Contains(body, "Powered by") == (locale == LocaleVI) {
				t.Errorf("%s/%s: powered-by credit not in the locale", locale, tmpl)
			}
			hasVi := viDiacritics.MatchString(body)
			if locale == LocaleEN && hasVi {
				t.Errorf("en/%s: Vietnamese text in English e-mail", tmpl)
			}
			if locale == LocaleVI && tmpl != TemplateSecurityNotice && !hasVi {
				t.Errorf("vi/%s: no Vietnamese text", tmpl)
			}
		}
	}
}

// Before the catalog, a vi recipient got the English subject.
func TestViRecipientGetsVietnameseSubject(t *testing.T) {
	e := NewTemplateEngine()
	subject, _, err := e.Render(TemplateVerifyEmail, VerifyEmailData{AppName: "App", Lang: Lang{Locale: "vi"}})
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Xác minh địa chỉ email của bạn" {
		t.Fatalf("subject = %q", subject)
	}
	subject, _, _ = e.Render(TemplateVerifyEmail, VerifyEmailData{AppName: "App"})
	if subject != "Verify your email address" {
		t.Fatalf("default subject = %q", subject)
	}
	subject, _, _ = e.Render(TemplateVerifyEmail, VerifyEmailData{AppName: "App", Lang: Lang{Locale: "ja"}})
	if subject != "Verify your email address" {
		t.Fatalf("unsupported locale subject = %q", subject)
	}
}

func TestUserValuesAreEscapedInEveryLocale(t *testing.T) {
	e := NewTemplateEngine()
	const evil = `<script>alert(1)</script>`
	for _, locale := range []string{LocaleEN, LocaleVI} {
		for tmpl, data := range allSamples(locale, evil) {
			_, body, err := e.Render(tmpl, data)
			if err != nil {
				t.Fatalf("%s/%s: %v", locale, tmpl, err)
			}
			if strings.Contains(body, evil) || strings.Contains(body, "<script>") {
				t.Errorf("%s/%s: unescaped user value in body", locale, tmpl)
			}
		}
	}
}

// A user value that looks like a placeholder must stay literal.
func TestValuesAreNotReExpanded(t *testing.T) {
	got := Text(LocaleEN, "welcome.heading", "{1}")
	if got != "Welcome to {1}!" {
		t.Fatalf("got %q", got)
	}
	if h := string(TextHTML(LocaleEN, "invite.line", "<b>x</b>", "{0}")); strings.Contains(h, "<b>") {
		t.Fatalf("value not escaped: %q", h)
	}
}

func TestFormatHelpersPerLocale(t *testing.T) {
	if got := FormatDuration(LocaleVI, 48*time.Hour); got != "2 ngày" {
		t.Errorf("vi days = %q", got)
	}
	if got := FormatDuration(LocaleEN, 48*time.Hour); got != "2 days" {
		t.Errorf("en days = %q", got)
	}
	if got := FormatDuration(LocaleVI, 24*time.Hour); got != "24 giờ" {
		t.Errorf("vi 24h = %q", got)
	}
	ts := time.Date(2026, 11, 3, 14, 5, 0, 0, time.UTC)
	if got := FormatDate(LocaleVI, ts); got != "03/11/2026" {
		t.Errorf("vi date = %q", got)
	}
	if got := FormatDate(LocaleEN, ts); got != "November 3, 2026" {
		t.Errorf("en date = %q", got)
	}
}
