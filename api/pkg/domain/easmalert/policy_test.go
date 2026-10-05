package easmalert

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		e    Exposure
		want Decision
	}{
		{"confirmed medium", Exposure{Severity: "medium", HasAsset: true, Attribution: "confirmed"}, Immediate},
		{"confirmed critical", Exposure{Severity: "critical", HasAsset: true, Attribution: "confirmed"}, Immediate},
		{"dependency high (takeover case, E13)", Exposure{Severity: "high", HasAsset: true, Attribution: "dependency"}, Immediate},
		{"no record medium", Exposure{Severity: "medium", HasAsset: true}, Immediate},
		{"confirmed low", Exposure{Severity: "low", HasAsset: true, Attribution: "confirmed"}, Digest},
		{"confirmed info", Exposure{Severity: "info", HasAsset: true, Attribution: "confirmed"}, Digest},
		{"needs_review high", Exposure{Severity: "high", HasAsset: true, Attribution: "needs_review"}, Digest},
		{"candidate critical", Exposure{Severity: "critical", HasAsset: true, Attribution: "candidate"}, Digest},
		{"monitor_only high", Exposure{Severity: "high", HasAsset: true, Attribution: "monitor_only"}, Digest},
		{"unlinked high", Exposure{Severity: "high"}, Digest},
		{"rejected critical", Exposure{Severity: "critical", HasAsset: true, Attribution: "rejected"}, Skip},
		{"deleted asset", Exposure{Severity: "critical", HasAsset: true, AssetDeleted: true, Attribution: "confirmed"}, Skip},
		{"unknown severity", Exposure{Severity: "bogus", HasAsset: true, Attribution: "confirmed"}, Digest},
	}
	for _, c := range cases {
		if got := Classify(c.e); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestLabel(t *testing.T) {
	for e, want := range map[Exposure]string{
		{}:               LabelUnlinked,
		{HasAsset: true}: "unrecorded",
		{HasAsset: true, Attribution: "needs_review"}: LabelUnverified,
		{HasAsset: true, Attribution: "candidate"}:    LabelUnverified,
		{HasAsset: true, Attribution: "confirmed"}:    "confirmed",
	} {
		if got := Label(e); got != want {
			t.Errorf("Label(%+v) = %q, want %q", e, got, want)
		}
	}
}

func TestNextDigestAt(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for now, want := range map[string]string{
		"2026-10-05T07:59:59Z":      "2026-10-05T08:00:00Z",
		"2026-10-05T08:00:00Z":      "2026-10-06T08:00:00Z",
		"2026-10-05T23:00:00Z":      "2026-10-06T08:00:00Z",
		"2026-10-05T09:00:00+07:00": "2026-10-05T08:00:00Z",
	} {
		if got := NextDigestAt(at(now)); !got.Equal(at(want)) {
			t.Errorf("NextDigestAt(%s) = %s, want %s", now, got, want)
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	if MaxSeverity("info", "high") != "high" || MaxSeverity("critical", "low") != "critical" || MaxSeverity("medium", "medium") != "medium" {
		t.Fatal("MaxSeverity")
	}
}
