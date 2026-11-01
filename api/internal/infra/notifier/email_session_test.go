package notifier

import (
	"bufio"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	emailpkg "github.com/openctemio/openctem/api/pkg/email"
)

// tarpit accepts connections and never sends a byte: an SMTP client waiting
// for the greeting blocks until something bounds the session.
func tarpit(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().String()
}

// routeSMTP sends every vetted SMTP dial to addr (the test relay) and
// records what was dialed.
func routeSMTP(t *testing.T, addr string) *[]string {
	t.Helper()
	var dialed []string
	prevResolve, prevDial := relayResolver, relayDialer
	relayResolver = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.0.2.25"), nil }
	relayDialer = func(ctx context.Context, timeout time.Duration, a string) (net.Conn, error) {
		dialed = append(dialed, a)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	t.Cleanup(func() { relayResolver, relayDialer = prevResolve, prevDial })
	return &dialed
}

// sendProbe sends one notification and returns the error itself, which Send
// flattens into the result text.
func sendProbe(c *EmailClient, ctx context.Context) error {
	return c.deliver(ctx, Message{Title: "probe", Body: "x"})
}

func tenantEmailClient(port int) *EmailClient {
	return &EmailClient{product: "test", config: EmailConfig{
		SMTPHost: "smtp.example.com", SMTPPort: port, FromEmail: "a@example.com", ToEmails: []string{"b@example.com"},
	}}
}

// A relay that accepts the connection and never answers is bounded by the
// session budget: the send returns instead of holding the worker.
func TestEmailSend_SessionBoundedWithoutCallerDeadline(t *testing.T) {
	routeSMTP(t, tarpit(t))
	prev := smtpSessionTimeout
	smtpSessionTimeout = 300 * time.Millisecond
	t.Cleanup(func() { smtpSessionTimeout = prev })

	done := make(chan error, 1)
	go func() { done <- sendProbe(tenantEmailClient(587), context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent relay was reported as delivered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send blocked past its session budget on a silent relay")
	}
}

// The caller's deadline wins when it is earlier, for implicit TLS too (the
// handshake is the first read).
func TestEmailSend_CallerDeadlineBoundsSession(t *testing.T) {
	routeSMTP(t, tarpit(t))
	for _, implicitTLS := range []bool{false, true} {
		c := tenantEmailClient(465)
		c.config.UseTLS = implicitTLS
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		err := sendProbe(c, ctx)
		cancel()
		if err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("implicit TLS %v: err %v after %v, want a failure within the caller's deadline", implicitTLS, err, time.Since(start))
		}
	}
}

// A stored relay on a port that is not a mail port is never dialed, and a
// new one is refused at construction.
func TestEmailSend_RefusesNonMailPort(t *testing.T) {
	dialed := routeSMTP(t, tarpit(t))
	for _, port := range []int{6379, 22, 5432, 9200, 11211, 80} {
		if err := sendProbe(tenantEmailClient(port), context.Background()); !errors.Is(err, emailpkg.ErrTenantPortNotAllowed) {
			t.Errorf("port %d: err = %v, want ErrTenantPortNotAllowed", port, err)
		}
		cfg := tenantEmailClient(port).config
		if _, err := NewEmailClient(Config{Email: &cfg}); !errors.Is(err, emailpkg.ErrTenantPortNotAllowed) {
			t.Errorf("NewEmailClient port %d: err = %v, want ErrTenantPortNotAllowed", port, err)
		}
	}
	if len(*dialed) != 0 {
		t.Fatalf("dialed %v for a refused port", *dialed)
	}
}

// The relay is dialed at the vetted address on the configured port.
func TestEmailSend_DialsVettedAddress(t *testing.T) {
	dialed := routeSMTP(t, tarpit(t))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = sendProbe(tenantEmailClient(2525), ctx)
	if len(*dialed) != 1 || (*dialed)[0] != "192.0.2.25:2525" {
		t.Fatalf("dialed %v, want exactly 192.0.2.25:2525", *dialed)
	}
}

// On a managed service the platform never speaks unauthenticated or
// clear-text SMTP, and never port 25, to a relay an organization chose: the
// relay is refused at construction and before the dial of a stored
// configuration; self-managed installs keep their relays.
func TestEmailSend_ManagedServiceTransportRules(t *testing.T) {
	dialed := routeSMTP(t, tarpit(t))
	emailpkg.SetManagedTenantRelay(true)
	t.Cleanup(func() { emailpkg.SetManagedTenantRelay(false) })

	cases := []struct {
		name string
		edit func(*EmailConfig)
		want error
	}{
		{"port 25", func(c *EmailConfig) { c.SMTPPort = 25; c.UseSTARTTLS = true; c.Username, c.Password = "u", "p" }, emailpkg.ErrTenantRelayPort25},
		{"no AUTH", func(c *EmailConfig) { c.SMTPPort = 587; c.UseSTARTTLS = true }, emailpkg.ErrTenantRelayNeedsAuth},
		{"no TLS", func(c *EmailConfig) { c.SMTPPort = 587; c.Username, c.Password = "u", "p" }, emailpkg.ErrTenantRelayNeedsTLS},
	}
	for _, tc := range cases {
		cfg := tenantEmailClient(587).config
		tc.edit(&cfg)
		if _, err := NewEmailClient(Config{Email: &cfg}); !errors.Is(err, tc.want) {
			t.Errorf("%s: NewEmailClient err = %v, want %v", tc.name, err, tc.want)
		}
		stored := &EmailClient{product: "test", config: cfg}
		if err := sendProbe(stored, context.Background()); !errors.Is(err, tc.want) {
			t.Errorf("%s: send err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if len(*dialed) != 0 {
		t.Fatalf("dialed %v for a refused relay", *dialed)
	}

	emailpkg.SetManagedTenantRelay(false)
	cfg := tenantEmailClient(25).config
	if _, err := NewEmailClient(Config{Email: &cfg}); err != nil {
		t.Fatalf("a self-managed install keeps port 25 without AUTH: %v", err)
	}
}

// fakeRelay is a minimal SMTP server that records the DATA of one message.
func fakeRelay(t *testing.T) (addr string, data <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
		w("220 relay.example.com ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				w("250 relay.example.com")
			case strings.HasPrefix(cmd, "DATA"):
				w("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				out <- b.String()
				w("250 ok")
			case strings.HasPrefix(cmd, "QUIT"):
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return ln.Addr().String(), out
}

// The notification channel sends through the shared pkg/email sender: the
// message it delivers has the shared format (Date, Message-ID on the sender
// domain, RFC 2047 subject, text and HTML parts) and a CR/LF in the title
// cannot start another header.
func TestEmailSend_UsesSharedSender(t *testing.T) {
	relay, data := fakeRelay(t)
	routeSMTP(t, relay)

	c := tenantEmailClient(2525)
	c.config.FromName = "Trung tâm Giám sát"
	c.config.ReplyTo = "reply@example.com"
	res, err := c.Send(context.Background(), Message{
		Title: "Lỗ hổng nghiêm trọng\r\nBcc: victim@example.net", Body: "chi tiết", Severity: "high",
		URL: "https://app.example.com/f/1", Fields: map[string]string{"Asset": "api.example.com"},
	})
	if err != nil || !res.Success {
		t.Fatalf("send: %v %+v", err, res)
	}
	var raw string
	select {
	case raw = <-data:
	case <-time.After(5 * time.Second):
		t.Fatal("relay got no message")
	}
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Bcc") != "" {
		t.Error("header injected through the title")
	}
	if !strings.HasSuffix(m.Header.Get("Message-ID"), "@example.com>") || m.Header.Get("Date") == "" {
		t.Errorf("Message-ID %q Date %q", m.Header.Get("Message-ID"), m.Header.Get("Date"))
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || !strings.Contains(subj, "Lỗ hổng nghiêm trọng") || !strings.Contains(subj, "[HIGH]") {
		t.Errorf("subject = %q (%v)", subj, err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q (%v)", m.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var parts []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(p)
		parts = append(parts, strings.SplitN(p.Header.Get("Content-Type"), ";", 2)[0]+"|"+string(b))
	}
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "text/plain|") || !strings.HasPrefix(parts[1], "text/html|") {
		t.Fatalf("parts = %d", len(parts))
	}
	if !strings.Contains(parts[0], "Asset: api.example.com") || !strings.Contains(parts[0], "https://app.example.com/f/1") {
		t.Errorf("text part lost the fields or link: %q", parts[0])
	}
}
