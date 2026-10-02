package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/openctemio/api/pkg/logger"
)

// newTestConn dials a throwaway websocket server and returns the client-side
// conn (good enough for exercising Client.Close, which only needs a real conn).
func newTestConn(t *testing.T) *websocket.Conn {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Hold the server side open until the test ends.
		t.Cleanup(func() { _ = c.Close() })
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial test ws: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return conn
}

// Regression: SendMessage used to release c.mu between the closed-check and the
// channel send, so a concurrent Close could close(c.send) first and the send
// panicked ("send on closed channel"), crashing the process on a routine
// disconnect. Hammer SendMessage from many goroutines while Close runs — any
// regression shows up as a panic (and as a race with -race).
func TestClient_SendMessageCloseRace_NoPanic(t *testing.T) {
	for i := 0; i < 50; i++ {
		c := &Client{
			conn:   newTestConn(t),
			send:   make(chan []byte, 4),
			logger: logger.NewNop(),
			ID:     "test",
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < 20; j++ {
					_ = c.SendMessage(&Message{Type: "ping"})
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c.Close()
		}()

		close(start)
		wg.Wait()

		// Idempotent double-close must also be safe.
		c.Close()
	}
}

// Regression: after Run exits (server shutdown), Broadcast / RegisterClient /
// UnregisterClient used to send on channels nobody reads and block the caller
// forever — stalling graceful shutdown. They must now return promptly.
func TestHub_SendersDoNotHangAfterShutdown(t *testing.T) {
	h := NewHub(logger.NewNop())
	ctx, cancel := context.WithCancel(context.Background())

	ran := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(ran)
	}()
	cancel()
	<-ran // hub fully stopped

	doneCh := make(chan struct{})
	go func() {
		h.Broadcast("tenant:t1", NewMessage(MessageTypeEvent), "t1")
		h.DeliverLocal(&BroadcastMessage{Channel: "tenant:t1"})
		c := &Client{conn: newTestConn(t), send: make(chan []byte, 1), logger: logger.NewNop()}
		h.RegisterClient(c)
		h.UnregisterClient(c)
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// ok — no hang
	case <-time.After(5 * time.Second):
		t.Fatal("hub channel senders hung after shutdown")
	}
}
