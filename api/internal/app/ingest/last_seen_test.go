package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

func TestAssetSeenAt(t *testing.T) {
	report := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	earlier := report.Add(-72 * time.Hour)
	cases := []struct {
		name string
		v    any
		want time.Time
	}{
		{"RFC 3339", earlier.Format(time.RFC3339), earlier},
		{"space layout", earlier.Format("2006-01-02 15:04:05"), earlier},
		{"epoch number", float64(earlier.Unix()), earlier},
		{"epoch string", "1791892800", time.Unix(1791892800, 0).UTC()},
		{"missing", nil, report},
		{"garbage", "yesterday", report},
		{"after the report", report.Add(time.Hour).Format(time.RFC3339), report},
		{"equal to the report", report.Format(time.RFC3339), report},
		{"epoch in milliseconds", float64(earlier.UnixMilli()), report},
		{"before 2000", "1999-12-31T23:59:59Z", report},
		{"negative", float64(-5), report},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &ctis.Asset{Properties: ctis.Properties{"last_seen": tc.v}}
			if got := assetSeenAt(ca, report); !got.Equal(tc.want) {
				t.Fatalf("assetSeenAt = %v, want %v", got, tc.want)
			}
		})
	}
}
