package websocket

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// F-7: unit tests for the Redis bridge. We avoid spinning a real Redis
// (would drag in a container or fake) — the two properties we care about
// are covered with a lightweight in-memory publisher stand-in:
//
//   1. Broadcast with a publisher attached calls Publish() with the
//      correct envelope (channel + tenant + serialized message) — i.e.
//      messages go to the cross-pod channel instead of only the local
//      hub.
//   2. DeliverLocal pushes a BroadcastMessage onto the hub's broadcast
//      channel without re-publishing (so the subscriber side of the
//      bridge never causes loops).
//
// The Start() goroutine itself wraps go-redis pubsub; behaviour of the
// third-party client is not ours to test.

type capturePublisher struct {
	published []*BroadcastMessage
}

func (c *capturePublisher) Publish(_ context.Context, m *BroadcastMessage) error {
	c.published = append(c.published, m)
	return nil
}

// Hub.Run consumes h.broadcast; for these tests we read directly from the
// channel after a short timeout so we do not depend on the full Hub
// loop.

func TestHub_BroadcastWithPublisher_UsesPublisher(t *testing.T) {
	hub := NewHub(logger.NewNop())
	cap := &capturePublisher{}
	hub.SetPublisher(cap)

	msg := NewMessage(MessageTypeEvent).WithChannel("finding:1").WithData(map[string]string{"k": "v"})
	hub.Broadcast("finding:1", msg, "tenant-A")

	if len(cap.published) != 1 {
		t.Fatalf("published %d messages, want 1", len(cap.published))
	}
	got := cap.published[0]
	if got.Channel != "finding:1" || got.TenantID != "tenant-A" {
		t.Fatalf("published envelope = %+v", got)
	}

	// The Hub's local broadcast chan MUST stay empty when a publisher
	// handles the message — avoiding double delivery (local + pubsub
	// fan-in both landing on the same pod).
	select {
	case m := <-hub.broadcast:
		t.Fatalf("broadcast chan should be empty but got %+v", m)
	case <-time.After(10 * time.Millisecond):
	}
}

func TestHub_DeliverLocal_DoesNotRepublish(t *testing.T) {
	hub := NewHub(logger.NewNop())
	cap := &capturePublisher{}
	hub.SetPublisher(cap)

	msg := NewMessage(MessageTypeEvent).WithChannel("scan:1")
	hub.DeliverLocal(&BroadcastMessage{
		Channel:  "scan:1",
		Message:  msg,
		TenantID: "tenant-A",
	})

	// Must NOT re-publish — otherwise every pod would bounce every
	// inbound message back to Redis and we'd have an amplification loop.
	if len(cap.published) != 0 {
		t.Fatalf("DeliverLocal must not call Publish (%d calls)", len(cap.published))
	}

	// Must land on the local broadcast channel.
	select {
	case m := <-hub.broadcast:
		if m.Channel != "scan:1" {
			t.Fatalf("local delivery channel = %q", m.Channel)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("expected local delivery")
	}
}

func TestHub_BroadcastWithoutPublisher_UsesLocalChannel(t *testing.T) {
	hub := NewHub(logger.NewNop())
	msg := NewMessage(MessageTypeEvent).WithChannel("finding:1")
	hub.Broadcast("finding:1", msg, "tenant-A")

	select {
	case m := <-hub.broadcast:
		if m.Channel != "finding:1" {
			t.Fatalf("channel = %q", m.Channel)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("expected local delivery when no publisher is attached")
	}
}

// Verify the wire-payload envelope round-trips so a receiving pod decodes
// the same thing we published. Protects against accidental JSON-tag
// regressions.
func TestWirePayload_RoundTrip(t *testing.T) {
	orig := &BroadcastMessage{
		Channel:  "tenant:42",
		Message:  NewMessage(MessageTypeEvent).WithChannel("tenant:42").WithData("hello"),
		TenantID: "tenant-42",
	}
	raw, err := json.Marshal(orig.Message)
	if err != nil {
		t.Fatal(err)
	}
	env := wirePayload{
		Channel:  orig.Channel,
		TenantID: orig.TenantID,
		Message:  raw,
	}
	buf, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	var decoded wirePayload
	if err := json.Unmarshal(buf, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Channel != orig.Channel || decoded.TenantID != orig.TenantID {
		t.Fatalf("envelope mismatch: %+v", decoded)
	}
	var restored Message
	if err := json.Unmarshal(decoded.Message, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Channel != orig.Message.Channel {
		t.Fatalf("message channel mismatch: got %q", restored.Channel)
	}
}
