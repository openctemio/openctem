package scan

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var uuidLike = regexp.MustCompile(`[0-9a-f]{8}-?[0-9a-f]{4}|[0-9a-f]{16,}`)

func domainErr(t *testing.T, err error) *shared.DomainError {
	t.Helper()
	var de *shared.DomainError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want a domain error", err)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("err = %v, want a validation refusal", err)
	}
	if uuidLike.MatchString(de.Message) {
		t.Errorf("message carries an id-like token: %q", de.Message)
	}
	return de
}

func refusedOf(t *testing.T, de *shared.DomainError) []scopedom.Refusal {
	t.Helper()
	d, ok := de.Details.(map[string]any)
	if !ok {
		t.Fatalf("details = %#v", de.Details)
	}
	rs, ok := d["refused"].([]scopedom.Refusal)
	if !ok {
		t.Fatalf("details.refused = %#v", d["refused"])
	}
	return rs
}

func TestNothingToScan_OnlyUnresolvedIsADNSFactWithoutZones(t *testing.T) {
	de := domainErr(t, NothingToScanError([]scanzone.Uncovered{
		{Target: "go.example.com", Reason: "does not resolve in DNS", Kind: scanzone.KindUnresolved},
	}))
	if de.Code != CodeNoResolvingTargets {
		t.Errorf("code = %s, want %s", de.Code, CodeNoResolvingTargets)
	}
	if !strings.Contains(de.Message, "go.example.com does not resolve in DNS") {
		t.Errorf("message = %q", de.Message)
	}
	if strings.Contains(strings.ToLower(de.Message), "zone") {
		t.Errorf("message mentions zones for an unresolved name: %q", de.Message)
	}
	rs := refusedOf(t, de)
	if len(rs) != 1 || rs[0].Code != scopedom.RefusalUnresolved || rs[0].Target != "go.example.com" || rs[0].Message == "" {
		t.Errorf("refused = %+v", rs)
	}
}

func TestNothingToScan_GroupsEachReason(t *testing.T) {
	de := domainErr(t, NothingToScanError([]scanzone.Uncovered{
		{Target: "a.example.com", Kind: scanzone.KindUnresolved},
		{Target: "b.example.com", Kind: scanzone.KindUnresolved},
		{Target: "10.2.0.1", Reason: "private", Kind: scanzone.KindOutsideZones},
		{Target: "10.1.0.1", Reason: `scan zone "dc" has no sensors assigned`, Kind: scanzone.KindZoneNoSensor},
		{Target: "127.0.0.1", Kind: scanzone.KindDenyList},
	}))
	if de.Code != codeNoZoneCoverage {
		t.Errorf("code = %s", de.Code)
	}
	for _, want := range []string{
		"2 targets do not resolve in DNS (a.example.com, b.example.com)",
		"10.2.0.1 is a private address outside every scan zone",
		"10.1.0.1 is in a scan zone with no sensor",
		"127.0.0.1 is in the built-in deny list",
		"add the range to a scan zone",
		"assign a sensor to the zone",
	} {
		if !strings.Contains(de.Message, want) {
			t.Errorf("message %q lacks %q", de.Message, want)
		}
	}
	codes := map[string]string{}
	for _, r := range refusedOf(t, de) {
		codes[r.Target] = r.Code
	}
	want := map[string]string{
		"a.example.com": scopedom.RefusalUnresolved, "b.example.com": scopedom.RefusalUnresolved,
		"10.2.0.1": scopedom.RefusalZoneNone, "10.1.0.1": scopedom.RefusalZoneNoSensor, "127.0.0.1": scopedom.RefusalDenyList,
	}
	for k, v := range want {
		if codes[k] != v {
			t.Errorf("%s: code %q, want %q", k, codes[k], v)
		}
	}
}

func TestNothingToScan_BoundsTheList(t *testing.T) {
	var us []scanzone.Uncovered
	for i := 0; i < maxListedUncovered+20; i++ {
		us = append(us, scanzone.Uncovered{Target: "h" + strings.Repeat("x", i%5) + ".example.com", Kind: scanzone.KindUnresolved})
	}
	de := domainErr(t, NothingToScanError(us))
	if !strings.Contains(de.Message, "and 117 more") {
		t.Errorf("message = %q", de.Message)
	}
	if n := len(refusedOf(t, de)); n != maxListedUncovered {
		t.Errorf("listed %d, want %d", n, maxListedUncovered)
	}
}

func TestRecordZonePlan_PolicyOnlyKeepsItsCode(t *testing.T) {
	plan := &zonePlan{
		PolicyRefused: []string{`scan zone "dc": no sensor accepts`},
		Uncovered:     []scanzone.Uncovered{{Target: "10.1.0.1", Kind: scanzone.KindSensorPolicy}},
	}
	de := domainErr(t, recordZonePlan(plan, map[string]any{}))
	if de.Code != codeSensorPolicyRefused {
		t.Errorf("code = %s, want %s", de.Code, codeSensorPolicyRefused)
	}
	plan.Uncovered = append(plan.Uncovered, scanzone.Uncovered{Target: "go.example.com", Kind: scanzone.KindUnresolved})
	de = domainErr(t, recordZonePlan(plan, map[string]any{}))
	if de.Code != codeNoZoneCoverage || !strings.Contains(de.Message, "go.example.com does not resolve in DNS") {
		t.Errorf("mixed: code %s message %q", de.Code, de.Message)
	}
}
