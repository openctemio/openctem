package notifier

import (
	"context"
	"errors"
	"net"
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
	prevResolve, prevDial := resolveSMTPHost, dialSMTP
	resolveSMTPHost = func(context.Context, string) (net.IP, error) { return net.ParseIP("192.0.2.25"), nil }
	dialSMTP = func(ctx context.Context, a string) (net.Conn, error) {
		dialed = append(dialed, a)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	t.Cleanup(func() { resolveSMTPHost, dialSMTP = prevResolve, prevDial })
	return &dialed
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
	go func() { done <- tenantEmailClient(587).sendSMTP(context.Background(), []byte("x")) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent relay was reported as delivered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendSMTP blocked past its session budget on a silent relay")
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
		err := c.sendSMTP(ctx, []byte("x"))
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
		if err := tenantEmailClient(port).sendSMTP(context.Background(), []byte("x")); !errors.Is(err, emailpkg.ErrTenantPortNotAllowed) {
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
	_ = tenantEmailClient(2525).sendSMTP(ctx, []byte("x"))
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
		if err := stored.sendSMTP(context.Background(), []byte("x")); !errors.Is(err, tc.want) {
			t.Errorf("%s: sendSMTP err = %v, want %v", tc.name, err, tc.want)
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
