package sensor

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSanitizeLocalPolicyReport(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	if SanitizeLocalPolicyReport(nil) != nil {
		t.Fatal("nil")
	}
	for _, state := range []string{"", "allowed", "ENFORCED-ish", "paused"} {
		if SanitizeLocalPolicyReport(&LocalPolicyReport{State: state}) != nil {
			t.Errorf("state %q accepted", state)
		}
	}

	got := SanitizeLocalPolicyReport(&LocalPolicyReport{
		State: " Enforced ", Source: "FILE", Digest: strings.ToUpper(digest), KillSwitch: true,
		Summary: &LocalPolicySummary{
			TargetsAllow: -7, TargetsDeny: -1, Ports: "80,443,8000-8999", MaxRPS: 1 << 30,
			Tools:  []string{"nuclei", "NUCLEI", "bad tool", strings.Repeat("x", 100), "httpx"},
			Checks: []string{},
		},
		Warnings: []string{"ok", "bidi \u202ehidden\u202c and\nnewline", "", strings.Repeat("w", 400)},
	})
	if got.State != LocalPolicyEnforced || got.Source != "file" || got.Digest != digest || !got.KillSwitch {
		t.Fatalf("report %+v", got)
	}
	s := got.Summary
	if s.TargetsAllow != -1 || s.TargetsDeny != 0 || s.Ports != "80,443,8000-8999" || s.MaxRPS != maxLocalPolicyCount {
		t.Fatalf("summary %+v", s)
	}
	if strings.Join(s.Tools, ",") != "nuclei,httpx" || s.Checks == nil || len(s.Checks) != 0 {
		t.Fatalf("tools %v checks %v", s.Tools, s.Checks)
	}
	if len(got.Warnings) != 3 || strings.ContainsAny(got.Warnings[1], "\u202e\u202c\n") || len([]rune(got.Warnings[2])) != maxLocalPolicyWarningLen {
		t.Fatalf("warnings %q", got.Warnings)
	}

	// Bad digest, source and ports are dropped; an absent policy carries no
	// summary or digest.
	got = SanitizeLocalPolicyReport(&LocalPolicyReport{State: "enforced", Source: "platform", Digest: "md5:x",
		Summary: &LocalPolicySummary{Ports: "80; rm -rf /"}})
	if got.Source != "" || got.Digest != "" || got.Summary.Ports != "" {
		t.Fatalf("%+v %+v", got, got.Summary)
	}
	got = SanitizeLocalPolicyReport(&LocalPolicyReport{State: "absent", Digest: digest, Summary: &LocalPolicySummary{}})
	if got.Digest != "" || got.Summary != nil {
		t.Fatalf("absent %+v", got)
	}
}

func TestLocalPolicyReport_DisplayState(t *testing.T) {
	var none *LocalPolicyReport
	for r, want := range map[*LocalPolicyReport]string{
		none:                         LocalPolicyUnknown,
		{State: LocalPolicyEnforced}: LocalPolicyEnforced,
		{State: LocalPolicyAbsent}:   LocalPolicyAbsent,
		{State: LocalPolicyEnforced, KillSwitch: true}: LocalPolicyPaused,
	} {
		if got := r.DisplayState(); got != want {
			t.Errorf("%+v: %s, want %s", r, got, want)
		}
	}
	if none.Enforced() || (&LocalPolicyReport{State: LocalPolicyAbsent}).Enforced() || !(&LocalPolicyReport{State: LocalPolicyEnforced}).Enforced() {
		t.Fatal("Enforced")
	}
}

func TestMergeLocalPolicyReport(t *testing.T) {
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	stored := &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1, Summary: &LocalPolicySummary{TargetsAllow: 3}, Warnings: []string{"w"}}

	// A slim heartbeat of the same policy keeps the summary and warnings.
	m := MergeLocalPolicyReport(stored, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1, KillSwitch: true})
	if m.Summary == nil || m.Summary.TargetsAllow != 3 || len(m.Warnings) != 1 || !m.KillSwitch {
		t.Fatalf("merged %+v", m)
	}
	// Another policy replaces it.
	if m := MergeLocalPolicyReport(stored, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d2}); m.Summary != nil {
		t.Fatalf("new digest kept the old summary: %+v", m)
	}
	if m := MergeLocalPolicyReport(stored, &LocalPolicyReport{State: LocalPolicyAbsent}); m.State != LocalPolicyAbsent || m.Summary != nil {
		t.Fatalf("absent %+v", m)
	}
	if MergeLocalPolicyReport(stored, nil) != stored || MergeLocalPolicyReport(nil, nil) != nil {
		t.Fatal("nil next keeps stored")
	}
}

func TestLocalPolicyEvent(t *testing.T) {
	tenantID := shared.NewID()
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	at := time.Now()
	s := &Sensor{ID: shared.NewID(), TenantID: &tenantID}
	for _, tc := range []struct {
		prev, next *LocalPolicyReport
		summary    string
	}{
		{nil, &LocalPolicyReport{State: LocalPolicyAbsent}, "No local policy"},
		{nil, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}, "Local policy enforced"},
		{&LocalPolicyReport{State: LocalPolicyAbsent}, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}, "Local policy enforced"},
		{&LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d2}, "Local policy changed"},
		{&LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1, KillSwitch: true}, "Paused by the local kill switch"},
		{&LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1, KillSwitch: true}, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}, "Local kill switch released"},
		{&LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}, &LocalPolicyReport{State: LocalPolicyAbsent}, "No local policy"},
	} {
		s.LocalPolicy = tc.prev
		e, ok := LocalPolicyEvent(s, tc.next, at)
		if !ok || e.Summary != tc.summary || e.Type != EventLocalPolicyChanged || e.Type.Category() != CategoryUpdates {
			t.Errorf("%+v -> %+v: %v %+v", tc.prev, tc.next, ok, e)
		}
	}
	s.LocalPolicy = &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1}
	if _, ok := LocalPolicyEvent(s, &LocalPolicyReport{State: LocalPolicyEnforced, Digest: d1, Warnings: []string{"x"}}, at); ok {
		t.Fatal("an unchanged policy is not an event")
	}
	if _, ok := LocalPolicyEvent(&Sensor{ID: shared.NewID()}, &LocalPolicyReport{State: LocalPolicyAbsent}, at); ok {
		t.Fatal("a platform sensor has no timeline")
	}
}

func TestLocalPolicyRefusal(t *testing.T) {
	for msg, want := range map[string]string{
		"refused by local policy: targets.deny: 10.20.5.9 is in 10.20.5.0/24":                  "targets.deny",
		"refused by local policy: kill_switch: kill switch file /etc/openctem/STOP is present": "kill_switch",
		"  refused by local policy: allow_interactsh: no":                                      "allow_interactsh",
		"refused by local policy: <script>: x":                                                 "unknown",
	} {
		rule, ok := LocalPolicyRefusal(msg)
		if !ok || rule != want {
			t.Errorf("%q: %q %v, want %q", msg, rule, ok, want)
		}
	}
	for _, msg := range []string{"", "scan failed: exit 1", "invalid scan target: refused by local policy: x"} {
		if _, ok := LocalPolicyRefusal(msg); ok {
			t.Errorf("%q parsed as a refusal", msg)
		}
	}
	e := LocalPolicyRefusalEvent(shared.NewID(), shared.NewID(), "c1", "targets.deny", "refused by local policy: targets.deny: x\u202e", time.Now())
	if e.Type != EventJobRefusedByLocalPolicy || e.Type.Category() != CategoryJobs || e.Details["command_id"] != "c1" ||
		strings.ContainsRune(e.Details["reason"].(string), '\u202e') {
		t.Fatalf("%+v", e)
	}
}
