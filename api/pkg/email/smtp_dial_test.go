package email

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// stubNetwork replaces the resolve and dial seams for one test.
func stubNetwork(t *testing.T, resolve func(context.Context, string) (net.IP, error),
	dial func(context.Context, time.Duration, string) (net.Conn, error)) {
	t.Helper()
	origResolve, origDial := resolveSMTPHost, dialSMTP
	resolveSMTPHost, dialSMTP = resolve, dial
	t.Cleanup(func() { resolveSMTPHost, dialSMTP = origResolve, origDial })
}

func testSender(timeout time.Duration) *SMTPSender {
	return NewSMTPSender(Config{
		Host:    "mail.tenant.example",
		Port:    2525,
		From:    "noreply@tenant.example",
		Timeout: timeout,
	})
}

func testMessage() *Message {
	return &Message{To: []string{"user@tenant.example"}, Subject: "s", Body: "b"}
}

// The tenant controls Host. The sender must dial the address the SSRF guard
// vetted, never the hostname: a second resolution at dial time is the
// DNS-rebinding window.
func TestSMTPSender_DialsTheVettedIPNotTheHostname(t *testing.T) {
	var dialed string
	stubNetwork(t,
		func(_ context.Context, host string) (net.IP, error) {
			if host != "mail.tenant.example" {
				t.Fatalf("resolved %q, want the configured host", host)
			}
			return net.ParseIP("203.0.113.7"), nil
		},
		func(_ context.Context, _ time.Duration, addr string) (net.Conn, error) {
			dialed = addr
			return nil, errors.New("stop here")
		})

	err := testSender(time.Second).Send(context.Background(), testMessage())
	if err == nil {
		t.Fatal("expected the stubbed dial error")
	}
	if dialed != "203.0.113.7:2525" {
		t.Fatalf("dialed %q, want the vetted IP 203.0.113.7:2525", dialed)
	}
}

func TestSMTPSender_GuardRefusalNeverDials(t *testing.T) {
	dialedAny := false
	stubNetwork(t,
		func(context.Context, string) (net.IP, error) {
			return nil, errors.New("host resolves to blocked address 169.254.169.254")
		},
		func(context.Context, time.Duration, string) (net.Conn, error) {
			dialedAny = true
			return nil, errors.New("must not dial")
		})

	err := testSender(time.Second).Send(context.Background(), testMessage())
	if err == nil || !strings.Contains(err.Error(), "smtp host rejected") {
		t.Fatalf("want an smtp host rejection, got %v", err)
	}
	if dialedAny {
		t.Fatal("a refused host must never be dialed")
	}
}

// A relay that accepts the connection and never sends its greeting must not
// hold the sending goroutine past the session budget.
func TestSMTPSender_SilentRelayTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			accepted <- c // hold it open, say nothing
		}
	}()
	defer func() {
		select {
		case c := <-accepted:
			_ = c.Close()
		default:
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	stubNetwork(t,
		func(context.Context, string) (net.IP, error) { return net.ParseIP("127.0.0.1"), nil },
		func(ctx context.Context, timeout time.Duration, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		})

	done := make(chan error, 1)
	go func() { done <- testSender(50*time.Millisecond).Send(context.Background(), testMessage()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error from a silent relay")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send hung on a relay that never answers")
	}
}

func TestSessionTimeout(t *testing.T) {
	if got := sessionTimeout(0); got != 120*time.Second {
		t.Fatalf("zero dial timeout: got %v", got)
	}
	if got := sessionTimeout(10 * time.Second); got != 40*time.Second {
		t.Fatalf("10s dial timeout: got %v", got)
	}
}
