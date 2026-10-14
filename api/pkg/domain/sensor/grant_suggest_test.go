package sensor

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func scanJob(tool string, targets ...string) UsageJob {
	p, _ := json.Marshal(map[string]any{"scanner": tool, "targets": targets})
	return UsageJob{Type: "scan", Payload: p}
}

func legacy() Grant {
	g := LegacyBroadGrant(shared.NewID(), shared.NewID())
	_ = g.Normalize()
	return *g
}

func TestSuggestGrant_ProfilesByUsage(t *testing.T) {
	zone := shared.NewID()
	zoned := scanJob("naabu", "10.0.0.5")
	zoned.ZoneID = &zone
	collect := UsageJob{Type: "collect", Payload: json.RawMessage(`{}`)}
	cases := []struct {
		name string
		kind SensorType
		u    GrantUsage
		want string
	}{
		{"public scans only", SensorTypeWorker, GrantUsage{Complete: true, Jobs: []UsageJob{scanJob("subfinder", "example.com"), scanJob("httpx", "https://example.com")}}, ProfileEASMExternal},
		{"private targets", SensorTypeWorker, GrantUsage{Complete: true, Jobs: []UsageJob{scanJob("httpx", "10.1.2.3")}}, ProfileInternalScanner},
		{"collector", SensorTypeCollector, GrantUsage{Complete: true, PushIngest: true, Jobs: []UsageJob{collect}}, ProfileCollector},
		{"push only", SensorTypeWorker, GrantUsage{Complete: true, PushIngest: true}, ProfileCollector},
		{"idle worker gets the kind default", SensorTypeWorker, GrantUsage{Complete: true}, ProfileInternalScanner},
		{"idle EASM sensor gets the kind default", SensorTypeEASM, GrantUsage{Complete: true}, ProfileEASMExternal},
		{"credentials", SensorTypeWorker, GrantUsage{Complete: true, Jobs: []UsageJob{{Type: "scan",
			Payload: json.RawMessage(`{"scanner":"httpx","targets":["10.0.0.1"],"config":{"password":"hunter2-secret-value"}}`)}}}, ProfileAuthenticatedScanner},
		{"zoned private scan", SensorTypeWorker, GrantUsage{Complete: true, Jobs: []UsageJob{zoned}}, ProfileInternalScanner},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cur := legacy()
			s := SuggestGrant(cur, c.kind, c.u, releasedContract)
			if s.Profile != c.want {
				t.Fatalf("profile %q (reason %q), want %q", s.Profile, s.Reason, c.want)
			}
			if w := Widened(cur, *s.Grant); len(w) > 0 {
				t.Fatalf("suggestion widens %v", w)
			}
			for _, j := range c.u.Jobs {
				if r := s.Grant.admitReleased(j.Type, j.Payload, j.ZoneID); r != nil {
					t.Fatalf("suggestion refuses a job of the window: %v", r)
				}
			}
			if s.Grant.TrustLevel != cur.TrustLevel || len(s.Grant.RemoteActions) != len(cur.RemoteActions) {
				t.Fatalf("trust or remote actions changed: %+v", s.Grant)
			}
		})
	}
}

func TestSuggestGrant_ZoneBound(t *testing.T) {
	zone, assigned := shared.NewID(), shared.NewID()
	j := scanJob("naabu", "10.0.0.5")
	j.ZoneID = &zone
	s := SuggestGrant(legacy(), SensorTypeWorker, GrantUsage{Complete: true, Jobs: []UsageJob{j}, AssignedZones: []shared.ID{assigned}}, releasedContract)
	if s.Profile != ProfileInternalScanner || len(s.Grant.ZoneIDs) != 2 {
		t.Fatalf("zones: %+v", s.Grant)
	}
	if s.Usage.ZoneCount != 1 || !s.Usage.PrivateTargets || s.Usage.PublicTargets {
		t.Fatalf("summary: %+v", s.Usage)
	}
}

func TestSuggestGrant_NoFitAndIncomplete(t *testing.T) {
	// A T2 job (custom templates) fits no profile: nothing is suggested.
	t2 := UsageJob{Type: "scan", Payload: json.RawMessage(`{"scanner":"nuclei","targets":["example.com"],"custom_templates":[{"name":"x"}]}`)}
	if s := SuggestGrant(legacy(), SensorTypeWorker, GrantUsage{Complete: true, Jobs: []UsageJob{t2}}, releasedContract); s.Profile != "" || s.Reason != SuggestReasonNoFit || s.Grant != nil {
		t.Fatalf("T2 job: %+v", s)
	}
	// A truncated window proves nothing.
	if s := SuggestGrant(legacy(), SensorTypeWorker, GrantUsage{Complete: false}, releasedContract); s.Profile != "" || s.Reason != SuggestReasonIncomplete {
		t.Fatalf("incomplete: %+v", s)
	}
}

// The suggestion is never wider than the current grant, whatever it is: a
// narrowed grant with a zone limit, a tool list, a target scope and no push
// ingest never gets a profile back that lifts any of them.
func TestSuggestGrant_NeverWiderThanCurrent(t *testing.T) {
	zone := shared.NewID()
	cur, _ := NewGrantFromProfile(shared.NewID(), shared.NewID(), ProfileEASMExternal, nil)
	cur.TrustLevel = TrustTrusted
	cur.Tools = []string{"httpx"}
	cur.TargetDomains = []string{"example.com"}
	_ = cur.Normalize()
	usages := []GrantUsage{
		{Complete: true},
		{Complete: true, PushIngest: true},
		{Complete: true, Jobs: []UsageJob{scanJob("httpx", "a.example.com")}},
		{Complete: true, Jobs: []UsageJob{scanJob("naabu", "10.0.0.1")}, AssignedZones: []shared.ID{zone}},
	}
	for i, u := range usages {
		s := SuggestGrant(*cur, SensorTypeWorker, u, releasedContract)
		if s.Grant == nil {
			continue
		}
		if w := Widened(*cur, *s.Grant); len(w) > 0 {
			t.Fatalf("usage %d: suggestion %q widens %v", i, s.Profile, w)
		}
	}
	// The same profile as now: nothing to apply.
	plain, _ := NewGrantFromProfile(shared.NewID(), shared.NewID(), ProfileEASMExternal, nil)
	_ = plain.Normalize()
	if s := SuggestGrant(*plain, SensorTypeEASM, GrantUsage{Complete: true}, releasedContract); s.Grant != nil || s.Reason != SuggestReasonAlreadyNarrow {
		t.Fatalf("already narrow: %+v", s)
	}
}

// The tier a job is checked at is the one the sensor's tool contract gives
// it: a tool the contract raises to T2 fits no profile.
func TestSuggestGrant_ContractTier(t *testing.T) {
	u := GrantUsage{Complete: true, Jobs: []UsageJob{scanJob("httpx", "example.com")}}
	raise := func(string) *ToolContract { return &ToolContract{Tier: "T2"} }
	if s := SuggestGrant(legacy(), SensorTypeWorker, u, raise); s.Grant != nil {
		t.Fatalf("contract T2 must not fit a T1 profile: %+v", s.Profile)
	}
}
