package coverage

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestIsGap(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	rule := Rule{Capability: "probe.http", Every: 72 * time.Hour}
	at := func(h int) *time.Time { v := now.Add(-time.Duration(h) * time.Hour); return &v }
	for name, c := range map[string]struct {
		row  Row
		want bool
	}{
		"fresh success":          {Row{State: StateCovered, LastSuccessAt: at(10), CreatedAt: now.Add(-1000 * time.Hour)}, false},
		"success past 2x":        {Row{State: StateCovered, LastSuccessAt: at(145), CreatedAt: now.Add(-1000 * time.Hour)}, true},
		"never, new row":         {Row{State: StateDue, CreatedAt: now.Add(-time.Hour)}, false},
		"never, old row":         {Row{State: StateFailed, CreatedAt: now.Add(-200 * time.Hour)}, true},
		"blocked is not a gap":   {Row{State: StateBlocked, CreatedAt: now.Add(-1000 * time.Hour)}, false},
		"not applicable":         {Row{State: StateNotApplicable, CreatedAt: now.Add(-1000 * time.Hour)}, false},
		"paused is not a gap":    {Row{State: StatePaused, CreatedAt: now.Add(-1000 * time.Hour)}, false},
		"queued long, no succes": {Row{State: StateQueued, CreatedAt: now.Add(-200 * time.Hour)}, true},
		"parked dead name":       {Row{State: StateCovered, LastOutcome: OutcomeNoAnswer, LastSuccessAt: at(300), CreatedAt: now.Add(-1000 * time.Hour)}, false},
		"dead name recheck runs": {Row{State: StateQueued, LastOutcome: OutcomeNoAnswer, LastSuccessAt: at(300), CreatedAt: now.Add(-1000 * time.Hour)}, false},
	} {
		row := c.row
		if got := IsGap(rule, &row, now); got != c.want {
			t.Errorf("%s: gap = %v, want %v", name, got, c.want)
		}
	}
}

func TestView(t *testing.T) {
	now := time.Now()
	id := shared.NewID()
	rules := []Rule{{Capability: "resolve.dns", Every: 24 * time.Hour}, {Capability: "probe.http", Every: 72 * time.Hour}}
	old := now.Add(-100 * time.Hour)
	rows := []Row{
		{Pair: Pair{Capability: "resolve.dns"}, State: StateCovered, LastSuccessAt: &old, CreatedAt: old},
		{Pair: Pair{Capability: "dns.dangling"}, State: StateCovered, LastSuccessAt: &now, CreatedAt: old},
	}
	v := View(id, rules, rows, now)
	if len(v.Entries) != 3 || v.Gaps != 1 {
		t.Fatalf("view = %+v", v)
	}
	if e := v.Entries[1]; e.Capability != "probe.http" || e.State != StateDue || e.Reason != ReasonNotPlanned {
		t.Errorf("unplanned rule entry = %+v", e)
	}
	if e := v.Entries[2]; e.Capability != "dns.dangling" || e.Gap {
		t.Errorf("extra row entry = %+v", e)
	}
}

func TestRulesCoverTheNetworkChain(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if r.Every <= 0 || !ValidCapability(r.Capability) {
			t.Errorf("bad rule %+v", r)
		}
		seen[string(r.Type)+"/"+r.SubType+" "+r.Capability] = true
	}
	for _, k := range []string{"subdomain/ probe.http", "service/open_port probe.http", "service/http vuln.templates", "ip_address/ scan.ports"} {
		if !seen[k] {
			t.Errorf("missing rule %s", k)
		}
	}
	if !IsWebPort(8443) || IsWebPort(22) {
		t.Error("web port set is wrong")
	}
}

func TestDueTargetAndBackoff(t *testing.T) {
	if got := (DueTarget{Name: "203.0.113.7:8443:tcp", Type: "service", SubType: "open_port"}).Target(); got != "203.0.113.7:8443" {
		t.Errorf("open port target = %q", got)
	}
	if got := (DueTarget{Name: "www.example.com", Type: "subdomain"}).Target(); got != "www.example.com" {
		t.Errorf("name target = %q", got)
	}
	if got := (DueTarget{Name: "https://www.example.com", Type: "service", SubType: "http"}).Target(); got != "https://www.example.com" {
		t.Errorf("origin target = %q", got)
	}
	if Backoff(72*time.Hour, 1) != time.Hour || Backoff(72*time.Hour, 3) != 4*time.Hour || Backoff(2*time.Hour, 5) != 2*time.Hour || Backoff(30*24*time.Hour, 20) != 24*time.Hour {
		t.Error("backoff is wrong")
	}
}

func TestHealthAlerts(t *testing.T) {
	for name, c := range map[string]struct {
		h    CapabilityHealth
		want string
	}{
		"healthy":            {CapabilityHealth{Applicable: 10, OK: 5}, ""},
		"gap":                {CapabilityHealth{Applicable: 10, Gaps: 2, OK: 5}, AlertGap},
		"output drop":        {CapabilityHealth{Applicable: 30, NoOutput: 20}, AlertOutputDrop},
		"few without output": {CapabilityHealth{Applicable: 30, NoOutput: 19}, ""},
		"some output":        {CapabilityHealth{Applicable: 30, NoOutput: 25, OK: 1}, ""},
		"failing":            {CapabilityHealth{Applicable: 3, Failing: 1, OK: 2}, AlertFailing},
	} {
		got := ""
		if a := c.h.Alerts(); len(a) > 0 {
			got = a[0]
		}
		if got != c.want {
			t.Errorf("%s: alerts = %v, want %q", name, c.h.Alerts(), c.want)
		}
	}
}

func TestIsWebPlausiblePort(t *testing.T) {
	for _, p := range []int{80, 443, 2083, 8765, 8000, 8999, 10443, 9443} {
		if !IsWebPlausiblePort(p) {
			t.Errorf("port %d should be plausible", p)
		}
	}
	for _, p := range []int{22, 25, 3306, 7999, 11000, 0} {
		if IsWebPlausiblePort(p) {
			t.Errorf("port %d should not be plausible", p)
		}
	}
}
