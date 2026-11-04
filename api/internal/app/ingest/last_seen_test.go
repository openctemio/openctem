package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"
)

func TestAssetSeenAt(t *testing.T) {
	report := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	earlier := report.Add(-72 * time.Hour)
	at := func(t time.Time) *time.Time { return &t }
	cases := []struct {
		name string
		v    *time.Time
		want time.Time
	}{
		{"earlier than the report", at(earlier), earlier},
		{"other zone", at(earlier.In(time.FixedZone("x", 7*3600))), earlier},
		{"missing", nil, report},
		{"after the report", at(report.Add(time.Hour)), report},
		{"equal to the report", at(report), report},
		{"before 2000", at(time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC)), report},
		{"zero time", at(time.Time{}), report},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &ctis.Asset{LastSeenAt: tc.v}
			if got := assetSeenAt(ca, report); !got.Equal(tc.want) {
				t.Fatalf("assetSeenAt = %v, want %v", got, tc.want)
			}
		})
	}
	// properties.last_seen carries no meaning in CTIS 2.0.
	legacy := &ctis.Asset{Properties: ctis.Properties{"last_seen": earlier.Format(time.RFC3339)}}
	if got := assetSeenAt(legacy, report); !got.Equal(report) {
		t.Fatalf("properties.last_seen was read: %v", got)
	}
	if got := assetSeenAt(nil, report); !got.Equal(report) {
		t.Fatalf("nil asset: %v", got)
	}
}
