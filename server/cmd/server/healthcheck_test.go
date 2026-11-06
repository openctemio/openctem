package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeHealth(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ok.URL+"/health", http.StatusFound)
	}))
	defer redirect.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()

	// A port nothing listens on.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + l.Addr().String() + "/health"
	_ = l.Close()

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"200", ok.URL + "/health", 0},
		{"503", down.URL + "/health", 1},
		{"redirect is not followed", redirect.URL + "/health", 1},
		{"connection refused", closed, 1},
		{"timeout", slow.URL + "/health", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if got := probeHealth(&stderr, c.url, 100*time.Millisecond); got != c.want {
				t.Fatalf("probeHealth(%s) = %d, want %d (stderr %q)", c.url, got, c.want, stderr.String())
			}
		})
	}
}

func TestRunHealthcheckRejectsBadPort(t *testing.T) {
	for _, v := range []string{"abc", "0", "70000", "8080/../x"} {
		t.Setenv("SERVER_PORT", v)
		var stderr bytes.Buffer
		if got := runHealthcheck(&stderr); got != 1 || !strings.Contains(stderr.String(), "invalid SERVER_PORT") {
			t.Fatalf("SERVER_PORT=%q: got %d, stderr %q", v, got, stderr.String())
		}
	}
}

func TestRunHealthcheckUsesServerPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	t.Setenv("SERVER_PORT", port)
	var stderr bytes.Buffer
	if got := runHealthcheck(&stderr); got != 0 {
		t.Fatalf("got %d, stderr %q", got, stderr.String())
	}
}
