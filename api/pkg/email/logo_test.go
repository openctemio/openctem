package email

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestLogoPNGIsTheLockup(t *testing.T) {
	cfg, err := png.DecodeConfig(bytes.NewReader(logoPNG))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Width != 280 || cfg.Height != 43 {
		t.Errorf("logo is %dx%d, want 280x43 (2x of 140x22)", cfg.Width, cfg.Height)
	}
}

func TestEveryTemplateHasTheBrandHeader(t *testing.T) {
	e := NewTemplateEngine()
	cases := map[Template]any{
		TemplateVerifyEmail:       VerifyEmailData{AppName: "OpenCTEM"},
		TemplatePasswordReset:     PasswordResetData{AppName: "OpenCTEM"},
		TemplatePasswordChanged:   PasswordChangedData{AppName: "OpenCTEM"},
		TemplateWelcome:           WelcomeData{AppName: "OpenCTEM"},
		TemplateTeamInvitation:    TeamInvitationData{AppName: "OpenCTEM"},
		TemplateMemberSuspended:   MemberStatusChangeData{AppName: "OpenCTEM"},
		TemplateMemberReactivated: MemberStatusChangeData{AppName: "OpenCTEM"},
		TemplateSecurityNotice:    SecurityNoticeData{AppName: "OpenCTEM"},
		TemplateAccountSetup:      AccountSetupData{AppName: "OpenCTEM"},
	}
	for name, data := range cases {
		_, body, err := e.Render(name, data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(body, `<img src="cid:logo" width="140" height="22" alt="OpenCTEM"`) {
			t.Errorf("%s: no embedded logo with the text fallback", name)
		}
		if strings.Contains(body, `class="logo"`) {
			t.Errorf("%s: text logo next to the image", name)
		}
	}
}

func TestOperatorBrandGetsInkTextNotTheOpenCTEMImage(t *testing.T) {
	e := NewTemplateEngine()
	_, body, err := e.Render(TemplateWelcome, WelcomeData{AppName: `Acme <b>X</b>`})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "cid:") {
		t.Error("operator brand got an image")
	}
	if !strings.Contains(body, `<div class="logo">Acme &lt;b&gt;X&lt;/b&gt;</div>`) {
		t.Errorf("operator name not rendered escaped in the header: %s", body[strings.Index(body, `class="logo"`):][:80])
	}
	if usesLogo(body) {
		t.Error("usesLogo true for an operator brand")
	}
}

func TestTemplatesUseBrandInkNotBlueAndNoRemoteImages(t *testing.T) {
	src, err := os.ReadFile("templates.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(src), []byte("#2563eb")) {
		t.Error("templates still use the old blue")
	}
	// An image in a mail must be attached (cid:), never fetched.
	for _, m := range regexp.MustCompile(`(?i)<img[^>]+src="([^"]+)"`).FindAllSubmatch(src, -1) {
		if !bytes.HasPrefix(m[1], []byte("cid:")) && !bytes.Contains(m[1], []byte("{{")) {
			t.Errorf("remote image in a template: %s", m[1])
		}
	}
	if regexp.MustCompile(`(?i)url\(\s*['"]?http`).Match(src) {
		t.Error("remote CSS image in a template")
	}
}

func TestBuildMessageEmbedsTheLogoAsRelatedPart(t *testing.T) {
	s := NewSMTPSender(Config{From: "no-reply@example.com", FromName: "OpenCTEM"})
	body := `<html><img src="cid:logo"></html>`
	raw := s.buildMessage(&Message{
		To: []string{"a@example.com"}, Subject: "Hi", Body: body, IsHTML: true,
		Inline: []InlineImage{{CID: logoCID, ContentType: "image/png", Data: logoPNG}},
	})
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/related" {
		t.Fatalf("content type %q (%v)", m.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	p1, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	var html bytes.Buffer
	_, _ = html.ReadFrom(p1)
	if !strings.Contains(html.String(), body) {
		t.Error("html part lost")
	}
	p2, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if p2.Header.Get("Content-ID") != "<logo>" {
		t.Errorf("Content-ID = %q", p2.Header.Get("Content-ID"))
	}
	var enc bytes.Buffer
	_, _ = enc.ReadFrom(p2)
	img, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(enc.String()), "\r\n", ""))
	if err != nil || !bytes.Equal(img, logoPNG) {
		t.Errorf("image part does not round-trip: %v", err)
	}
}

func TestBuildMessageWithoutInlineStaysSinglePart(t *testing.T) {
	s := NewSMTPSender(Config{From: "no-reply@example.com"})
	raw := string(s.buildMessage(&Message{To: []string{"a@example.com"}, Subject: "Hi", Body: "<p>x</p>", IsHTML: true}))
	if !strings.Contains(raw, "Content-Type: text/html; charset=UTF-8") || strings.Contains(raw, "multipart") {
		t.Errorf("unexpected structure: %s", raw)
	}
}
