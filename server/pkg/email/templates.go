package email

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/openctemio/openctem/server/pkg/brand"
)

// Template represents a predefined email template type.
type Template string

const (
	// TemplateVerifyEmail is the email verification template.
	TemplateVerifyEmail Template = "verify_email"
	// TemplatePasswordReset is the password reset template.
	TemplatePasswordReset Template = "password_reset"
	// TemplatePasswordChanged is the password changed notification template.
	TemplatePasswordChanged Template = "password_changed"
	// TemplateWelcome is the welcome email template.
	TemplateWelcome Template = "welcome"
	// TemplateTeamInvitation is the team invitation template.
	TemplateTeamInvitation Template = "team_invitation"
	// TemplateMemberSuspended notifies a user their tenant access was suspended.
	TemplateMemberSuspended Template = "member_suspended"
	// TemplateMemberReactivated notifies a user their tenant access was restored.
	TemplateMemberReactivated Template = "member_reactivated"
	// TemplateSecurityNotice tells a user about a security change to their
	// own account (2FA turned off, a recovery code used).
	TemplateSecurityNotice Template = "security_notice"
	// TemplateAccountSetup carries the one-time set-password link for an account
	// an administrator created.
	TemplateAccountSetup Template = "account_setup"
)

// Branding is the instance brand's part of every email: an optional footer
// line and the "Powered by OpenCTEM" credit (docs/architecture/brand.md).
// Each template's data embeds it.
type Branding struct {
	FooterText string
	PoweredBy  bool
}

// poweredByName is the upstream product a "Powered by" credit names; it is
// fixed whatever the configured brand is.
const poweredByName = "OpenCTEM"

// FooterHTML renders the footer line and the credit, escaped; "" when
// neither is set.
func (b Branding) FooterHTML() template.HTML { return b.footer(DefaultLocale) }

func (b Branding) footer(locale string) template.HTML {
	var buf bytes.Buffer
	if t := strings.TrimSpace(b.FooterText); t != "" {
		buf.WriteString("<p>")
		for i, line := range strings.Split(t, "\n") {
			if i > 0 {
				buf.WriteString("<br>")
			}
			buf.WriteString(template.HTMLEscapeString(line))
		}
		buf.WriteString("</p>")
	}
	if b.PoweredBy {
		buf.WriteString("<p>" + template.HTMLEscapeString(Text(locale, "common.poweredBy", poweredByName)) + "</p>")
	}
	return template.HTML(buf.String()) // #nosec G203 -- every part is escaped above
}

// SecurityNoticeData holds data for the account security notice.
type SecurityNoticeData struct {
	UserName   string
	Email      string
	Subject    string // also the heading
	Message    string
	OccurredAt string
	IPAddress  string
	AppName    string
	Branding
	Lang
}

// VerifyEmailData holds data for the email verification template.
type VerifyEmailData struct {
	UserName        string
	Email           string
	VerificationURL string
	ExpiresIn       string
	AppName         string
	Branding
	Lang
}

// PasswordResetData holds data for the password reset template.
type PasswordResetData struct {
	UserName    string
	Email       string
	ResetURL    string
	ExpiresIn   string
	AppName     string
	IPAddress   string
	RequestedAt string
	Branding
	Lang
}

// PasswordChangedData holds data for the password changed notification.
type PasswordChangedData struct {
	UserName  string
	Email     string
	ChangedAt string
	IPAddress string
	AppName   string
	Branding
	Lang
}

// WelcomeData holds data for the welcome email template.
type WelcomeData struct {
	UserName string
	Email    string
	LoginURL string
	AppName  string
	Branding
	Lang
}

// TeamInvitationData holds data for the team invitation template.
type TeamInvitationData struct {
	InviterName   string
	TeamName      string
	InvitationURL string
	ExpiresIn     string
	AppName       string
	Branding
	Lang
}

// AccountSetupData holds data for the account-setup (set your password) email.
type AccountSetupData struct {
	UserName  string
	TeamName  string
	SetupURL  string
	ExpiresIn string
	AppName   string
	Branding
	Lang
}

// MemberStatusChangeData holds data for the suspend/reactivate notifications.
type MemberStatusChangeData struct {
	UserName  string
	TeamName  string
	ActorName string // Admin who performed the action; may be empty
	AppURL    string // Where the user can go to see status (login page)
	AppName   string
	Branding
	Lang
}

// TemplateEngine handles email template rendering.
type TemplateEngine struct {
	templates map[Template]*templateDef
}

type templateDef struct {
	// subject returns the subject line in the locale; values are plain text
	// (the message layer strips line breaks and encodes the header).
	subject  func(locale string, data any) string
	bodyTmpl *template.Template
}

// NewTemplateEngine creates a new template engine with all predefined templates.
func NewTemplateEngine() *TemplateEngine {
	engine := &TemplateEngine{
		templates: make(map[Template]*templateDef),
	}
	engine.registerTemplates()
	return engine
}

// Render renders a template with the given data.
func (e *TemplateEngine) Render(tmpl Template, data any) (subject string, body string, err error) {
	def, ok := e.templates[tmpl]
	if !ok {
		return "", "", fmt.Errorf("template %s not found", tmpl)
	}

	locale := DefaultLocale
	if c, ok := data.(localeCarrier); ok {
		locale = c.LocaleCode()
	}
	subject = def.subject(locale, data)

	// Render body template
	var bodyBuf bytes.Buffer
	if err := def.bodyTmpl.Execute(&bodyBuf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute body template: %w", err)
	}

	return subject, bodyBuf.String(), nil
}

// registerTemplates registers all predefined email templates.
func (e *TemplateEngine) registerTemplates() {
	e.templates[TemplateVerifyEmail] = &templateDef{
		subject:  func(l string, _ any) string { return Text(l, "verify.subject") },
		bodyTmpl: bodyTemplate("verify_email", verifyEmailTemplate),
	}
	e.templates[TemplatePasswordReset] = &templateDef{
		subject:  func(l string, _ any) string { return Text(l, "pwreset.subject") },
		bodyTmpl: bodyTemplate("password_reset", passwordResetTemplate),
	}
	e.templates[TemplatePasswordChanged] = &templateDef{
		subject:  func(l string, _ any) string { return Text(l, "pwchanged.subject") },
		bodyTmpl: bodyTemplate("password_changed", passwordChangedTemplate),
	}
	e.templates[TemplateWelcome] = &templateDef{
		subject: func(l string, d any) string {
			w, _ := d.(WelcomeData)
			return Text(l, "welcome.subject", w.AppName)
		},
		bodyTmpl: bodyTemplate("welcome", welcomeTemplate, template.FuncMap{"docsURL": func() string { return brand.Instance().Docs() + "/" }}),
	}
	e.templates[TemplateTeamInvitation] = &templateDef{
		subject: func(l string, d any) string {
			t, _ := d.(TeamInvitationData)
			return Text(l, "invite.subject", t.TeamName)
		},
		bodyTmpl: bodyTemplate("team_invitation", teamInvitationTemplate),
	}
	e.templates[TemplateMemberSuspended] = &templateDef{
		subject: func(l string, d any) string {
			m, _ := d.(MemberStatusChangeData)
			return Text(l, "suspended.subject", m.TeamName)
		},
		bodyTmpl: bodyTemplate("member_suspended", memberSuspendedTemplate),
	}
	e.templates[TemplateMemberReactivated] = &templateDef{
		subject: func(l string, d any) string {
			m, _ := d.(MemberStatusChangeData)
			return Text(l, "reactivated.subject", m.TeamName)
		},
		bodyTmpl: bodyTemplate("member_reactivated", memberReactivatedTemplate),
	}
	// The security notice's subject and message arrive already in the
	// recipient's language (the caller picks them from the catalog).
	e.templates[TemplateSecurityNotice] = &templateDef{
		subject: func(_ string, d any) string {
			n, _ := d.(SecurityNoticeData)
			return n.Subject
		},
		bodyTmpl: bodyTemplate("security_notice", securityNoticeTemplate),
	}
	e.templates[TemplateAccountSetup] = &templateDef{
		subject: func(l string, d any) string {
			a, _ := d.(AccountSetupData)
			return Text(l, "setup.subject", a.AppName, a.TeamName)
		},
		bodyTmpl: bodyTemplate("account_setup", accountSetupTemplate),
	}
}

const securityNoticeTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Subject}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef2f2; border: 1px solid #ef4444; border-radius: 4px; padding: 12px; margin: 20px 0; }
        .security-info { background: #f3f4f6; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{.Subject}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <p>{{.Message}}</p>

        <div class="security-info">
            {{if .OccurredAt}}{{t .Locale "common.time" .OccurredAt}}<br>{{end}}
            {{if .IPAddress}}{{t .Locale "common.ipAddress" .IPAddress}}{{end}}
        </div>

        <div class="warning">
            <strong>{{t .Locale "notice.wasntYou"}}</strong><br>
            {{t .Locale "notice.wasntYouBody"}}
        </div>

        <div class="footer">
            <p>{{t .Locale "common.sentTo" .Email}}</p>
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

// Email Templates (HTML)

const verifyEmailTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "verify.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .button { display: inline-block; background: #0A1628; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .button:hover { background: #1d4ed8; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "verify.heading"}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <p>{{t .Locale "verify.body"}}</p>

        <div style="text-align: center;">
            <a href="{{.VerificationURL}}" class="button">{{t .Locale "verify.button"}}</a>
        </div>

        <div class="warning">
            {{th .Locale "verify.expires" .ExpiresIn}}
        </div>

        <p>{{t .Locale "verify.ignore" .AppName}}</p>

        <p>{{t .Locale "common.linkFallback"}}</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.VerificationURL}}</p>

        <div class="footer">
            <p>{{t .Locale "common.sentTo" .Email}}</p>
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const passwordResetTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "pwreset.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .button { display: inline-block; background: #0A1628; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .button:hover { background: #1d4ed8; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
        .security-info { background: #f3f4f6; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "pwreset.heading"}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <p>{{t .Locale "pwreset.body"}}</p>

        <div style="text-align: center;">
            <a href="{{.ResetURL}}" class="button">{{t .Locale "pwreset.button"}}</a>
        </div>

        <div class="warning">
            {{th .Locale "pwreset.expires" .ExpiresIn}}
        </div>

        {{if .IPAddress}}
        <div class="security-info">
            <strong>{{t .Locale "pwreset.details"}}</strong><br>
            {{t .Locale "common.ipAddress" .IPAddress}}<br>
            {{if .RequestedAt}}{{t .Locale "common.time" .RequestedAt}}{{end}}
        </div>
        {{end}}

        <p>{{t .Locale "pwreset.ignore"}}</p>

        <p>{{t .Locale "common.linkFallback"}}</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.ResetURL}}</p>

        <div class="footer">
            <p>{{t .Locale "common.sentTo" .Email}}</p>
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const passwordChangedTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "pwchanged.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .alert { background: #dcfce7; border: 1px solid #22c55e; border-radius: 4px; padding: 12px; margin: 20px 0; }
        .warning { background: #fef2f2; border: 1px solid #ef4444; border-radius: 4px; padding: 12px; margin: 20px 0; }
        .security-info { background: #f3f4f6; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "pwchanged.heading"}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <div class="alert">
            {{if .ChangedAt}}{{t .Locale "pwchanged.alertAt" .ChangedAt}}{{else}}{{t .Locale "pwchanged.alert"}}{{end}}
        </div>

        {{if .IPAddress}}
        <div class="security-info">
            <strong>{{t .Locale "pwchanged.details"}}</strong><br>
            {{t .Locale "common.ipAddress" .IPAddress}}<br>
            {{if .ChangedAt}}{{t .Locale "common.time" .ChangedAt}}{{end}}
        </div>
        {{end}}

        <div class="warning">
            <strong>{{t .Locale "pwchanged.didnt"}}</strong><br>
            {{t .Locale "pwchanged.didntBody"}}
        </div>

        <div class="footer">
            <p>{{t .Locale "common.sentTo" .Email}}</p>
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const welcomeTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "welcome.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .button { display: inline-block; background: #0A1628; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .features { background: #f3f4f6; border-radius: 4px; padding: 20px; margin: 20px 0; }
        .features ul { margin: 0; padding-left: 20px; }
        .features li { margin: 8px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "welcome.heading" .AppName}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <p>{{t .Locale "welcome.intro" .AppName}}</p>

        <div class="features">
            <strong>{{t .Locale "welcome.features"}}</strong>
            <ul>
                <li>{{t .Locale "welcome.feature1"}}</li>
                <li>{{t .Locale "welcome.feature2"}}</li>
                <li>{{t .Locale "welcome.feature3"}}</li>
                <li>{{t .Locale "welcome.feature4"}}</li>
            </ul>
        </div>

        <div style="text-align: center;">
            <a href="{{.LoginURL}}" class="button">{{t .Locale "welcome.button"}}</a>
        </div>

        <p>{{th .Locale "welcome.docs" .AppName docsURL}}</p>

        <div class="footer">
            <p>{{t .Locale "common.sentTo" .Email}}</p>
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const teamInvitationTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "invite.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .button { display: inline-block; background: #0A1628; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
        .invite-box { background: #eff6ff; border: 1px solid #3b82f6; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
        .team-name { font-size: 20px; font-weight: bold; color: #1e40af; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "invite.heading"}}</h2>

        <p>{{t .Locale "common.hiThere"}}</p>

        <p>{{th .Locale "invite.line" .InviterName .AppName}}</p>

        <div class="invite-box">
            <div class="team-name">{{.TeamName}}</div>
        </div>

        <div style="text-align: center;">
            <a href="{{.InvitationURL}}" class="button">{{t .Locale "invite.accept"}}</a>
        </div>

        <div class="warning">
            {{th .Locale "invite.expires" .ExpiresIn}}
        </div>

        <p>{{t .Locale "invite.ignore"}}</p>

        <p>{{t .Locale "common.linkFallback"}}</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.InvitationURL}}</p>

        <div class="footer">
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const accountSetupTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "setup.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .button { display: inline-block; background: #0A1628; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "setup.heading"}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <p>{{th .Locale "setup.body" .TeamName .AppName}}</p>

        <div style="text-align: center;">
            <a href="{{.SetupURL}}" class="button">{{t .Locale "setup.button"}}</a>
        </div>

        <div class="warning">
            {{th .Locale "setup.expires" .ExpiresIn}}
        </div>

        <p>{{t .Locale "setup.ignore"}}</p>

        <p>{{t .Locale "setup.linkFallback"}}</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.SetupURL}}</p>

        <div class="footer">
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const memberSuspendedTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "suspended.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .alert { background: #fff7ed; border: 1px solid #f97316; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .alert-title { color: #c2410c; font-weight: bold; font-size: 16px; margin-bottom: 8px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .team-name { font-weight: bold; color: #1e40af; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "suspended.heading"}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <div class="alert">
            <div class="alert-title">{{th .Locale "suspended.alertTitle" .TeamName}}</div>
            <p style="margin: 0;">{{t .Locale "suspended.alertBody" .TeamName}}</p>
        </div>

        {{if .ActorName}}
        <p>{{th .Locale "suspended.actor" .ActorName}}</p>
        {{end}}

        <p>{{th .Locale "suspended.data"}}</p>

        <p>{{t .Locale "suspended.help" .AppName}}</p>

        <div class="footer">
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`

const memberReactivatedTemplate = `<!DOCTYPE html>
<html lang="{{lang .Locale}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{t .Locale "reactivated.title"}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #0A1628; }
        .button { display: inline-block; background: #0A1628; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .alert { background: #ecfdf5; border: 1px solid #10b981; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .alert-title { color: #047857; font-weight: bold; font-size: 16px; margin-bottom: 8px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .team-name { font-weight: bold; color: #047857; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{template "brandHeader" .AppName}}
        </div>

        <h2>{{t .Locale "reactivated.heading"}}</h2>

        <p>{{if .UserName}}{{t .Locale "common.hiName" .UserName}}{{else}}{{t .Locale "common.hi"}}{{end}}</p>

        <div class="alert">
            <div class="alert-title">{{th .Locale "reactivated.alertTitle" .TeamName}}</div>
            <p style="margin: 0;">{{t .Locale "reactivated.alertBody"}}</p>
        </div>

        {{if .ActorName}}
        <p>{{th .Locale "reactivated.actor" .ActorName}}</p>
        {{end}}

        <div style="text-align: center;">
            <a href="{{.AppURL}}" class="button">{{t .Locale "reactivated.button" .AppName}}</a>
        </div>

        <p>{{t .Locale "reactivated.help"}}</p>

        <div class="footer">
            <p>{{t .Locale "common.copyright" .AppName}}</p>
            {{footer .Locale .Branding}}
        </div>
    </div>
</body>
</html>`
