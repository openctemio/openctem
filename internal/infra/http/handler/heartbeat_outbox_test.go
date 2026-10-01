package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/sensor"
)

// The outbox block is decoded leniently like the rest of the heartbeat and
// clamped before it reaches the service.
func TestHeartbeatRequest_OutboxDecodeAndClamp(t *testing.T) {
	cases := []struct {
		name string
		body string
		want *sensor.OutboxStats
	}{
		{
			name: "absent field leaves the snapshot alone",
			body: `{"status":"running","version":"1.0.0"}`,
			want: nil,
		},
		{
			name: "explicit null is the same as absent",
			body: `{"status":"running","outbox":null}`,
			want: nil,
		},
		{
			name: "in range values pass through",
			body: `{"status":"running","outbox":{"pending_count":3,"pending_bytes":123456,"oldest_age_seconds":600,"dead_letter_count":1,"evicted_count":0}}`,
			want: &sensor.OutboxStats{PendingCount: 3, PendingBytes: 123456, OldestAgeSeconds: 600, DeadLetterCount: 1},
		},
		{
			name: "empty object is an empty outbox, not absent",
			body: `{"status":"running","outbox":{}}`,
			want: &sensor.OutboxStats{},
		},
		{
			name: "negative and absurd values are clamped",
			body: `{"status":"running","outbox":{"pending_count":-4,"pending_bytes":9000000000000000000,"oldest_age_seconds":999999999999,"dead_letter_count":99999999999,"evicted_count":-1}}`,
			want: &sensor.OutboxStats{
				PendingBytes:     sensor.MaxOutboxBytes,
				OldestAgeSeconds: sensor.MaxOutboxAgeSeconds,
				DeadLetterCount:  sensor.MaxOutboxCount,
			},
		},
		{
			name: "unknown outbox fields are ignored",
			body: `{"status":"running","outbox":{"pending_count":2,"future_field":"x"}}`,
			want: &sensor.OutboxStats{PendingCount: 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req HeartbeatRequest
			if err := json.NewDecoder(strings.NewReader(tc.body)).Decode(&req); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := req.Outbox.toOutboxStats()
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("got %+v, want nil", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("got nil, want %+v", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("got %+v, want %+v", *got, *tc.want)
			}
		})
	}
}

// A value that does not fit int64 fails only that field: the heartbeat handler
// keeps going with what decoded, so the rest of the heartbeat still lands.
func TestHeartbeatRequest_OutboxOverflowDoesNotLoseHeartbeat(t *testing.T) {
	body := `{"status":"running","version":"2.0.0","outbox":{"pending_count":1e30,"dead_letter_count":2}}`
	var req HeartbeatRequest
	err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
	if err == nil {
		t.Fatal("expected a decode error for an out-of-range number")
	}
	if req.Version != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", req.Version)
	}
	got := req.Outbox.toOutboxStats()
	if got == nil || got.DeadLetterCount != 2 || got.PendingCount != 0 {
		t.Errorf("outbox = %+v, want dead_letter_count=2 and pending_count=0", got)
	}
}
