package signer

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// SocketMode is the mode of the signer's socket: the signer's user and
// group (the API joins the group) may connect, nobody else.
const SocketMode = 0o660

// ListenUnix listens on a Unix socket at path with SocketMode. A stale
// socket left by an earlier run is replaced; any other file at path is
// refused. The caller sets a umask that keeps the socket from being created
// wider (cmd/signer does).
func ListenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("signer socket: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("signer socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("signer socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("signer socket: %w", err)
	}
	if err := os.Chmod(path, SocketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("signer socket: %w", err)
	}
	return ln, nil
}

// NewHTTPServer is the signer's HTTP/1.1 server with tight limits: its only
// client is the API, on the same host.
func NewHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
