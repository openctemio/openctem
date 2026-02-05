package email

import (
	"bytes"
	"fmt"
	"html/template"
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
)

// VerifyEmailData holds data for the email verification template.
type VerifyEmailData struct {
	UserName        string
	Email           string
	VerificationURL string
	ExpiresIn       string
	AppName         string
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
}

// PasswordChangedData holds data for the password changed notification.
type PasswordChangedData struct {
	UserName   string
	Email      string
	ChangedAt  string
	IPAddress  string
	AppName    string
	SupportURL string
}

// WelcomeData holds data for the welcome email template.
type WelcomeData struct {
	UserName   string
	Email      string
	LoginURL   string
	AppName    string
	SupportURL string
}

// TeamInvitationData holds data for the team invitation template.
type TeamInvitationData struct {
	InviterName   string
	TeamName      string
	InvitationURL string
	ExpiresIn     string
	AppName       string
}

// TemplateEngine handles email template rendering.
type TemplateEngine struct {
	templates map[Template]*templateDef
}

type templateDef struct {
	subjectTmpl *template.Template
	bodyTmpl    *template.Template
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

	// Render subject template
	var subjectBuf bytes.Buffer
	if err := def.subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute subject template: %w", err)
	}

	// Render body template
	var bodyBuf bytes.Buffer
	if err := def.bodyTmpl.Execute(&bodyBuf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute body template: %w", err)
	}

	return subjectBuf.String(), bodyBuf.String(), nil
}

// registerTemplates registers all predefined email templates.
func (e *TemplateEngine) registerTemplates() {
	// Verify Email
	e.templates[TemplateVerifyEmail] = &templateDef{
		subjectTmpl: template.Must(template.New("verify_email_subject").Parse("Verify your email address")),
		bodyTmpl:    template.Must(template.New("verify_email").Parse(verifyEmailTemplate)),
	}

	// Password Reset
	e.templates[TemplatePasswordReset] = &templateDef{
		subjectTmpl: template.Must(template.New("password_reset_subject").Parse("Reset your password")),
		bodyTmpl:    template.Must(template.New("password_reset").Parse(passwordResetTemplate)),
	}

	// Password Changed
	e.templates[TemplatePasswordChanged] = &templateDef{
		subjectTmpl: template.Must(template.New("password_changed_subject").Parse("Your password has been changed")),
		bodyTmpl:    template.Must(template.New("password_changed").Parse(passwordChangedTemplate)),
	}

	// Welcome
	e.templates[TemplateWelcome] = &templateDef{
		subjectTmpl: template.Must(template.New("welcome_subject").Parse("Welcome to {{.AppName}}")),
		bodyTmpl:    template.Must(template.New("welcome").Parse(welcomeTemplate)),
	}

	// Team Invitation
	e.templates[TemplateTeamInvitation] = &templateDef{
		subjectTmpl: template.Must(template.New("team_invitation_subject").Parse("You've been invited to join {{.TeamName}}")),
		bodyTmpl:    template.Must(template.New("team_invitation").Parse(teamInvitationTemplate)),
	}
}

// Email Templates (HTML)

const verifyEmailTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
        .button { display: inline-block; background: #2563eb; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .button:hover { background: #1d4ed8; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{.AppName}}</div>
        </div>

        <h2>Verify your email address</h2>

        <p>Hi{{if .UserName}} {{.UserName}}{{end}},</p>

        <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>

        <div style="text-align: center;">
            <a href="{{.VerificationURL}}" class="button">Verify Email Address</a>
        </div>

        <div class="warning">
            This link will expire in <strong>{{.ExpiresIn}}</strong>.
        </div>

        <p>If you didn't create an account with {{.AppName}}, you can safely ignore this email.</p>

        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.VerificationURL}}</p>

        <div class="footer">
            <p>This email was sent to {{.Email}}</p>
            <p>&copy; {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

const passwordResetTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
        .button { display: inline-block; background: #2563eb; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .button:hover { background: #1d4ed8; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
        .security-info { background: #f3f4f6; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{.AppName}}</div>
        </div>

        <h2>Reset your password</h2>

        <p>Hi{{if .UserName}} {{.UserName}}{{end}},</p>

        <p>We received a request to reset your password. Click the button below to create a new password:</p>

        <div style="text-align: center;">
            <a href="{{.ResetURL}}" class="button">Reset Password</a>
        </div>

        <div class="warning">
            This link will expire in <strong>{{.ExpiresIn}}</strong>.
        </div>

        {{if .IPAddress}}
        <div class="security-info">
            <strong>Request details:</strong><br>
            IP Address: {{.IPAddress}}<br>
            {{if .RequestedAt}}Time: {{.RequestedAt}}{{end}}
        </div>
        {{end}}

        <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>

        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.ResetURL}}</p>

        <div class="footer">
            <p>This email was sent to {{.Email}}</p>
            <p>&copy; {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

const passwordChangedTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .alert { background: #dcfce7; border: 1px solid #22c55e; border-radius: 4px; padding: 12px; margin: 20px 0; }
        .warning { background: #fef2f2; border: 1px solid #ef4444; border-radius: 4px; padding: 12px; margin: 20px 0; }
        .security-info { background: #f3f4f6; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{.AppName}}</div>
        </div>

        <h2>Your password has been changed</h2>

        <p>Hi{{if .UserName}} {{.UserName}}{{end}},</p>

        <div class="alert">
            Your password was successfully changed{{if .ChangedAt}} on {{.ChangedAt}}{{end}}.
        </div>

        {{if .IPAddress}}
        <div class="security-info">
            <strong>Change details:</strong><br>
            IP Address: {{.IPAddress}}<br>
            {{if .ChangedAt}}Time: {{.ChangedAt}}{{end}}
        </div>
        {{end}}

        <div class="warning">
            <strong>Didn't make this change?</strong><br>
            If you didn't change your password, your account may have been compromised. Please contact support immediately{{if .SupportURL}} at <a href="{{.SupportURL}}">{{.SupportURL}}</a>{{end}}.
        </div>

        <div class="footer">
            <p>This email was sent to {{.Email}}</p>
            <p>&copy; {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

const welcomeTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
        .button { display: inline-block; background: #2563eb; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .features { background: #f3f4f6; border-radius: 4px; padding: 20px; margin: 20px 0; }
        .features ul { margin: 0; padding-left: 20px; }
        .features li { margin: 8px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{.AppName}}</div>
        </div>

        <h2>Welcome to {{.AppName}}!</h2>

        <p>Hi{{if .UserName}} {{.UserName}}{{end}},</p>

        <p>Thank you for joining {{.AppName}}! Your account has been created and you're ready to get started.</p>

        <div class="features">
            <strong>What you can do:</strong>
            <ul>
                <li>Discover and inventory your assets</li>
                <li>Track vulnerabilities and findings</li>
                <li>Manage remediation workflows</li>
                <li>Generate compliance reports</li>
            </ul>
        </div>

        <div style="text-align: center;">
            <a href="{{.LoginURL}}" class="button">Go to Dashboard</a>
        </div>

        <p>Need help getting started? Check out our documentation or contact support{{if .SupportURL}} at <a href="{{.SupportURL}}">{{.SupportURL}}</a>{{end}}.</p>

        <div class="footer">
            <p>This email was sent to {{.Email}}</p>
            <p>&copy; {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

const teamInvitationTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Team Invitation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .container { background: #ffffff; border-radius: 8px; padding: 40px; border: 1px solid #e0e0e0; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
        .button { display: inline-block; background: #2563eb; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; text-align: center; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 12px; margin: 20px 0; font-size: 14px; }
        .invite-box { background: #eff6ff; border: 1px solid #3b82f6; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
        .team-name { font-size: 20px; font-weight: bold; color: #1e40af; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{.AppName}}</div>
        </div>

        <h2>You've been invited to join a team</h2>

        <p>Hi there,</p>

        <p><strong>{{.InviterName}}</strong> has invited you to join their team on {{.AppName}}:</p>

        <div class="invite-box">
            <div class="team-name">{{.TeamName}}</div>
        </div>

        <div style="text-align: center;">
            <a href="{{.InvitationURL}}" class="button">Accept Invitation</a>
        </div>

        <div class="warning">
            This invitation will expire in <strong>{{.ExpiresIn}}</strong>.
        </div>

        <p>If you don't want to join this team, you can safely ignore this email.</p>

        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; font-size: 12px; color: #666;">{{.InvitationURL}}</p>

        <div class="footer">
            <p>&copy; {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`
