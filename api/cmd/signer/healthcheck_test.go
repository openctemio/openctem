package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthcheck(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "signer.sock")

	if err := healthcheck("", time.Second); err == nil {
		t.Fatal("no socket configured: want an error")
	}
	if err := healthcheck(sock, 200*time.Millisecond); err == nil {
		t.Fatal("no socket file: want an error")
	}
	// A plain file at the socket path (what `test -S` would also reject).
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(sock, 200*time.Millisecond); err == nil {
		t.Fatal("regular file: want an error")
	}
	_ = os.Remove(sock)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if err := healthcheck(sock, time.Second); err != nil {
		t.Fatalf("listening socket: %v", err)
	}
	_ = ln.Close()
	if err := healthcheck(sock, 200*time.Millisecond); err == nil {
		t.Fatal("closed listener: want an error")
	}
}
