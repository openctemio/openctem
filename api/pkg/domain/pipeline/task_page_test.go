package pipeline

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestTaskCursor_RoundTrip(t *testing.T) {
	c := TaskCursor{CreatedAt: time.Date(2026, 10, 4, 10, 0, 0, 123456000, time.UTC), ID: shared.NewID()}
	got, err := DecodeTaskCursor(c.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(c.CreatedAt) || got.ID != c.ID {
		t.Fatalf("round trip = %+v, want %+v", got, c)
	}
	if strings.ContainsAny(c.Encode(), "+/=") {
		t.Fatalf("cursor %q is not URL-safe", c.Encode())
	}
}

func TestDecodeTaskCursor_RefusesAnythingElse(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, raw := range []string{
		"",
		"%%%",
		enc("no-separator"),
		enc("yesterday|" + shared.NewID().String()),
		enc("2026-10-04T10:00:00Z|not-a-uuid"),
		enc("2026-10-04T10:00:00Z|" + shared.NewID().String() + "' OR 1=1 --"),
		strings.Repeat("A", MaxTaskCursorLen+1),
	} {
		if _, err := DecodeTaskCursor(raw); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("DecodeTaskCursor(%q) err = %v, want validation", raw, err)
		}
	}
}
