package jobs

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// firstByte accepts one connection on a local listener and returns the first
// byte the client wrote: 0x16 opens a TLS handshake, '*' a plaintext RESP
// command.
func firstByte(t *testing.T, connect func(addr string)) byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	got := make(chan byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 1)
		if _, err := conn.Read(b); err == nil {
			got <- b[0]
		}
	}()

	go connect(ln.Addr().String())

	select {
	case b := <-got:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("client never connected")
		return 0
	}
}

func enqueueOnce(cfg ClientConfig) {
	c, err := NewClient(cfg, logger.NewNop())
	if err != nil {
		return
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = c.client.EnqueueContext(ctx, asynq.NewTask("probe", nil))
}

// A TLS-only Redis rejected every asynq connection ("SSL wrong version
// number") because the job client ignored REDIS_TLS_ENABLED while the cache
// client honored it.
func TestJobClient_UsesTLSWhenConfigured(t *testing.T) {
	b := firstByte(t, func(addr string) {
		enqueueOnce(ClientConfig{RedisAddr: addr, RedisTLS: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // handshake probe only, no server cert
			MinVersion:         tls.VersionTLS12,
		}})
	})
	if b != 0x16 {
		t.Fatalf("first byte = %#x, want 0x16 (TLS handshake)", b)
	}
}

func TestJobClient_PlaintextWithoutTLS(t *testing.T) {
	b := firstByte(t, func(addr string) { enqueueOnce(ClientConfig{RedisAddr: addr}) })
	if b != '*' {
		t.Fatalf("first byte = %q, want '*' (plaintext RESP)", b)
	}
}

func TestJobWorker_UsesTLSWhenConfigured(t *testing.T) {
	b := firstByte(t, func(addr string) {
		w, err := NewWorker(WorkerConfig{RedisAddr: addr, Concurrency: 1, RedisTLS: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // handshake probe only, no server cert
			MinVersion:         tls.VersionTLS12,
		}}, nil, logger.NewNop())
		if err != nil {
			return
		}
		_ = w.server.Ping()
	})
	if b != 0x16 {
		t.Fatalf("first byte = %#x, want 0x16 (TLS handshake)", b)
	}
}
