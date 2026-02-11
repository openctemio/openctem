package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// EmailClient implements the Client interface for email notifications via SMTP.
type EmailClient struct {
	config EmailConfig
}

// EmailConfig holds the SMTP configuration.
type EmailConfig struct {
	SMTPHost     string   // SMTP server host
	SMTPPort     int      // SMTP server port (25, 465, 587)
	Username     string   // SMTP username
	Password     string   // SMTP password
	FromEmail    string   // Sender email address
	FromName     string   // Sender display name
	ToEmails     []string // Recipient email addresses
	UseTLS       bool     // Use direct TLS (port 465)
	UseSTARTTLS  bool     // Use STARTTLS (port 587)
	SkipVerify   bool     // Skip TLS certificate verification (dev only)
	ReplyTo      string   // Optional reply-to address
	TemplateName string   // Optional custom template name
}

// NewEmailClient creates a new email notification client.
func NewEmailClient(config Config) (*EmailClient, error) {
	emailConfig := config.Email
	if emailConfig == nil {
		return nil, fmt.Errorf("email config is required")
	}

	if emailConfig.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if emailConfig.SMTPPort == 0 {
		return nil, fmt.Errorf("SMTP port is required")
	}
	if emailConfig.FromEmail == "" {
		return nil, fmt.Errorf("sender email is required")
	}
	if len(emailConfig.ToEmails) == 0 {
		return nil, fmt.Errorf("at least one recipient email is required")
	}

	return &EmailClient{
		config: *emailConfig,
	}, nil
}

// Provider returns the provider name.
func (c *EmailClient) Provider() string {
	return string(ProviderEmail)
}

// Send sends a notification email.
func (c *EmailClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	// Build HTML email body
	htmlBody, err := c.buildHTMLEmail(msg)
	if err != nil {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("build email body: %v", err),
		}, nil
	}

	// Build email headers
	subject := msg.Title
	if msg.Severity != "" {
		emoji := GetSeverityEmoji(msg.Severity)
		subject = fmt.Sprintf("%s [%s] %s", emoji, strings.ToUpper(msg.Severity), msg.Title)
	}

	// Build MIME message
	var emailBuf bytes.Buffer
	fmt.Fprintf(&emailBuf, "From: %s <%s>\r\n", c.config.FromName, c.config.FromEmail)
	fmt.Fprintf(&emailBuf, "To: %s\r\n", strings.Join(c.config.ToEmails, ", "))
	if c.config.ReplyTo != "" {
		fmt.Fprintf(&emailBuf, "Reply-To: %s\r\n", c.config.ReplyTo)
	}
	fmt.Fprintf(&emailBuf, "Subject: %s\r\n", subject)
	emailBuf.WriteString("MIME-Version: 1.0\r\n")
	emailBuf.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	fmt.Fprintf(&emailBuf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	emailBuf.WriteString("\r\n")
	emailBuf.WriteString(htmlBody)

	// Send via SMTP
	err = c.sendSMTP(ctx, emailBuf.Bytes())
	if err != nil {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("send email: %v", err),
		}, nil
	}

	return &SendResult{
		Success: true,
	}, nil
}

// TestConnection tests the SMTP configuration.
func (c *EmailClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		Title:    "OpenCTEM Test Notification",
		Body:     "This is a test notification to verify your email integration is working correctly.",
		Severity: "low",
	}
	return c.Send(ctx, testMsg)
}

// sendSMTP sends an email via SMTP.
func (c *EmailClient) sendSMTP(_ context.Context, message []byte) error {
	addr := net.JoinHostPort(c.config.SMTPHost, strconv.Itoa(c.config.SMTPPort))

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName:         c.config.SMTPHost,
		InsecureSkipVerify: c.config.SkipVerify, //nolint:gosec // Configurable for dev environments
	}

	var conn net.Conn
	var err error

	// Connect based on TLS settings
	if c.config.UseTLS {
		// Direct TLS connection (port 465)
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS dial: %w", err)
		}
	} else {
		// Plain connection (will upgrade with STARTTLS if needed)
		conn, err = net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
	}
	defer func() { _ = conn.Close() }()

	// Create SMTP client
	client, err := smtp.NewClient(conn, c.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("new SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// STARTTLS if required (port 587)
	if c.config.UseSTARTTLS && !c.config.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err = client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		}
	}

	// Authenticate if credentials provided
	if c.config.Username != "" && c.config.Password != "" {
		auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.SMTPHost)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	// Set sender
	if err = client.Mail(c.config.FromEmail); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}

	// Set recipients
	for _, to := range c.config.ToEmails {
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", to, err)
		}
	}

	// Send message body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("close writer: %w", err)
	}

	// Quit gracefully
	_ = client.Quit()

	return nil
}

// buildHTMLEmail builds an HTML email from the notification message.
func (c *EmailClient) buildHTMLEmail(msg Message) (string, error) {
	color := msg.Color
	if color == "" {
		color = GetSeverityColor(msg.Severity)
	}

	data := struct {
		Title      string
		Body       string
		Severity   string
		Color      string
		URL        string
		Fields     map[string]string
		FooterText string
		Timestamp  string
	}{
		Title:      msg.Title,
		Body:       msg.Body,
		Severity:   strings.ToUpper(msg.Severity),
		Color:      color,
		URL:        msg.URL,
		Fields:     msg.Fields,
		FooterText: msg.FooterText,
		Timestamp:  time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	tmpl, err := template.New("email").Parse(emailHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// emailHTMLTemplate is the HTML template for notification emails.
const emailHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 20px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: {{.Color}}; color: #fff; padding: 20px; }
        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }
        .severity-badge { display: inline-block; background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-bottom: 10px; }
        .content { padding: 20px; }
        .body { margin-bottom: 20px; white-space: pre-wrap; }
        .fields { background: #f8f9fa; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .field { margin-bottom: 10px; }
        .field:last-child { margin-bottom: 0; }
        .field-label { font-weight: 600; color: #666; font-size: 12px; text-transform: uppercase; margin-bottom: 2px; }
        .field-value { color: #333; }
        .button { display: inline-block; background: {{.Color}}; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; margin: 15px 0; }
        .button:hover { opacity: 0.9; }
        .footer { background: #f8f9fa; padding: 15px 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; }
        .footer a { color: {{.Color}}; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{if .Severity}}<div class="severity-badge">{{.Severity}}</div>{{end}}
            <h1>{{.Title}}</h1>
        </div>
        <div class="content">
            {{if .Body}}<div class="body">{{.Body}}</div>{{end}}
            {{if .Fields}}
            <div class="fields">
                {{range $key, $value := .Fields}}
                <div class="field">
                    <div class="field-label">{{$key}}</div>
                    <div class="field-value">{{$value}}</div>
                </div>
                {{end}}
            </div>
            {{end}}
            {{if .URL}}<a href="{{.URL}}" class="button">View Details</a>{{end}}
        </div>
        <div class="footer">
            {{if .FooterText}}{{.FooterText}}<br>{{end}}
            Sent by <a href="https://openctem.io">OpenCTEM</a> at {{.Timestamp}}
        </div>
    </div>
</body>
</html>`
