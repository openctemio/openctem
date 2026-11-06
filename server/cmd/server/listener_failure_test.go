package main

import (
	"errors"
	"net"
	"net/http"
	"testing"
)

func TestFatalListenerError(t *testing.T) {
	if fatalListenerError(nil) {
		t.Error("nil is not a failure")
	}
	if fatalListenerError(http.ErrServerClosed) {
		t.Error("a normal close is not a failure")
	}
	if !fatalListenerError(errors.New("listen tcp :8080: bind: address already in use")) {
		t.Error("a bind error must be fatal")
	}
}

// A real second listener on a busy port yields an error the helper treats as fatal.
func TestFatalListenerError_BusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener")
	}
	defer ln.Close()
	srv := &http.Server{Addr: ln.Addr().String()}
	if err := srv.ListenAndServe(); !fatalListenerError(err) {
		t.Fatalf("busy port error not fatal: %v", err)
	}
}
