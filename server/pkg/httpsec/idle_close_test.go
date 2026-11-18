package httpsec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
)

// reused makes one request through tr and reports whether it reused an idle
// connection.
func reused(t *testing.T, tr *http.Transport, url string) bool {
	t.Helper()
	var got bool
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { got = i.Reused },
	}))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return got
}

// Closing a console range closes the idle keep-alive connections of the
// registered transports, so none is reused into the closed range. Opening a
// range (or keeping the same list) leaves them alone.
func TestSetConsolePrivateCIDRs_NarrowingClosesIdleConnections(t *testing.T) {
	setPolicyForTest(t, &egressPolicy{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	// A plain transport stands in for a guarded one: the test server listens
	// on loopback, which the guard never dials.
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	registerGuardedTransport(tr)

	if err := SetConsolePrivateCIDRs([]string{"10.20.0.0/16", "192.168.77.0/24"}); err != nil {
		t.Fatal(err)
	}
	reused(t, tr, srv.URL)
	if err := SetConsolePrivateCIDRs([]string{"10.0.0.0/8", "192.168.77.0/24"}); err != nil { // wider: no close
		t.Fatal(err)
	}
	if !reused(t, tr, srv.URL) {
		t.Fatal("widening the list closed idle connections")
	}
	if err := SetConsolePrivateCIDRs([]string{"192.168.77.0/24"}); err != nil { // 10/8 closed
		t.Fatal(err)
	}
	if reused(t, tr, srv.URL) {
		t.Fatal("an idle connection survived closing a range")
	}
}

func TestNarrows(t *testing.T) {
	nets := func(cs ...string) []*net.IPNet {
		out := make([]*net.IPNet, 0, len(cs))
		for _, c := range cs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return out
	}
	cases := []struct {
		prev, next []string
		want       bool
	}{
		{nil, []string{"10.0.0.0/8"}, false},
		{[]string{"10.1.0.0/16"}, []string{"10.0.0.0/8"}, false},
		{[]string{"10.0.0.0/8"}, []string{"10.1.0.0/16"}, true},
		{[]string{"10.0.0.0/8"}, nil, true},
		{[]string{"192.168.77.0/24"}, []string{"192.168.78.0/24"}, true},
		{[]string{"fd12:3456:789a::/48"}, []string{"fd12:3456:789a::/48"}, false},
	}
	for _, c := range cases {
		if got := narrows(nets(c.prev...), nets(c.next...)); got != c.want {
			t.Errorf("narrows(%v, %v) = %v, want %v", c.prev, c.next, got, c.want)
		}
	}
}
