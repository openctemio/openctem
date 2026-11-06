package httpsec

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

// fakeResolver answers every name with the same address list.
type fakeResolver struct{ addrs []string }

func (f fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	out := make([]net.IPAddr, 0, len(f.addrs))
	for _, a := range f.addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

// scriptedDial fails the addresses in fail with their error and connects to
// any other, recording every attempt and whether it carried its own deadline.
type scriptedDial struct {
	fail      map[string]error
	tried     []string
	deadlines []bool
}

func (s *scriptedDial) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	s.tried = append(s.tried, host)
	_, has := ctx.Deadline()
	s.deadlines = append(s.deadlines, has)
	if err, ok := s.fail[host]; ok {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP(host), Port: 443}, Err: err}
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

const (
	v6a = "2600:1413:5000:a81::3ff9"
	v6b = "2600:1413:5000:a81::3ffa"
	v4a = "93.184.215.14"
	v4b = "93.184.215.15"
)

// A host without an IPv6 route: the AAAA answers fail at once and the dial
// still reaches IPv4, after one IPv6 attempt rather than all of them.
func TestDialFallsBackToIPv4WhenIPv6Unreachable(t *testing.T) {
	sd := &scriptedDial{fail: map[string]error{v6a: syscall.ENETUNREACH, v6b: syscall.ENETUNREACH}}
	d := guardedDialer{resolver: fakeResolver{[]string{v6a, v6b, v4a, v4b}}, dial: sd.dial}
	conn, err := d.dialContext(context.Background(), "tcp", "www.example.gov:443")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.Close()
	if want := []string{v6a, v4a}; strings.Join(sd.tried, ",") != strings.Join(want, ",") {
		t.Fatalf("tried %v, want %v (families interleaved)", sd.tried, want)
	}
}

// Every address fails: the error names each attempt, not only the last, and
// stays classifiable (errors.Is sees the causes).
func TestDialReportsEveryAttempt(t *testing.T) {
	sd := &scriptedDial{fail: map[string]error{
		v4a: syscall.ECONNRESET, v6a: syscall.ENETUNREACH, v4b: syscall.ETIMEDOUT}}
	d := guardedDialer{resolver: fakeResolver{[]string{v4a, v4b, v6a}}, dial: sd.dial}
	_, err := d.dialContext(context.Background(), "tcp", "www.example.gov:443")
	if err == nil {
		t.Fatal("want an error")
	}
	if want := []string{v4a, v6a, v4b}; strings.Join(sd.tried, ",") != strings.Join(want, ",") {
		t.Fatalf("tried %v, want %v", sd.tried, want)
	}
	for _, a := range []string{v4a, v4b, v6a} {
		if !strings.Contains(err.Error(), a) {
			t.Fatalf("error does not name %s: %v", a, err)
		}
	}
	if !errors.Is(err, syscall.ENETUNREACH) || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("causes not reachable through errors.Is: %v", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) {
		t.Fatalf("a dial failure must stay a net.Error for classification: %v", err)
	}
	// Every attempt but the last is bounded on its own.
	if want := []bool{true, true, false}; len(sd.deadlines) != 3 || sd.deadlines[0] != want[0] || sd.deadlines[1] != want[1] || sd.deadlines[2] != want[2] {
		t.Fatalf("attempt deadlines %v, want %v", sd.deadlines, want)
	}
}

// The SSRF check stays per resolved address: one blocked answer among public
// ones refuses the whole dial before any connection, in either family.
func TestDialRefusesWhenAnyAnswerIsBlocked(t *testing.T) {
	for _, blocked := range []string{"169.254.169.254", "127.0.0.1", "::1", "fe80::1", "fd00::1", "10.0.0.5"} {
		sd := &scriptedDial{}
		d := guardedDialer{resolver: fakeResolver{[]string{v6a, v4a, blocked}}, dial: sd.dial}
		_, err := d.dialContext(context.Background(), "tcp", "rebind.example:443")
		if !errors.Is(err, ErrBlockedDestination) {
			t.Fatalf("%s: want ErrBlockedDestination, got %v", blocked, err)
		}
		if len(sd.tried) != 0 {
			t.Fatalf("%s: dialed %v despite a blocked answer", blocked, sd.tried)
		}
	}
}

// A canceled request stops trying further addresses.
func TestDialStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sd := &scriptedDial{fail: map[string]error{v4a: syscall.ECONNRESET, v6a: syscall.ECONNRESET}}
	d := guardedDialer{resolver: fakeResolver{[]string{v4a, v6a}}, dial: func(c context.Context, n, a string) (net.Conn, error) {
		cancel()
		return sd.dial(c, n, a)
	}}
	if _, err := d.dialContext(ctx, "tcp", "x.example:443"); err == nil {
		t.Fatal("want an error")
	}
	if len(sd.tried) != 1 {
		t.Fatalf("tried %v after cancel", sd.tried)
	}
}

func TestInterleaveFamilies(t *testing.T) {
	in := []net.IP{net.ParseIP(v4a), net.ParseIP(v4b), net.ParseIP(v6a), net.ParseIP(v6b)}
	got := interleaveFamilies(in)
	want := []string{v4a, v6a, v4b, v6b}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
