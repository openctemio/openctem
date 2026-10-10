package scangov

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	saTrusted = "5a000000-0000-4000-8000-000000000001"
	saOther   = "5a000000-0000-4000-8000-000000000002"
	groupOps  = "60000000-0000-4000-8000-000000000001"
	roleCAB   = "70000000-0000-4000-8000-000000000001"
)

func mustRule(t *testing.T, c Conditions) Rule {
	t.Helper()
	rs, err := Normalize([]Rule{{Name: "r", Enabled: true, Conditions: c, Requirement: Requirement{Approvals: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return rs[0]
}

func TestRequesterConditions_Origins(t *testing.T) {
	r := mustRule(t, Conditions{Origins: []string{"API_KEY", "service_account", "mcp", "ci"}})
	cases := map[Origin]bool{OriginUI: false, OriginSystem: false, OriginAPIKey: true, OriginServiceAccount: true, OriginMCP: true, OriginCI: true}
	for o, want := range cases {
		if got := r.Conditions.Matches(Facts{Requester: &Requester{Origin: o}}); got != want {
			t.Errorf("origin %s: %v, want %v", o, got, want)
		}
	}
	if !r.Conditions.Matches(Facts{}) {
		t.Error("an unknown requester must be caught (fail closed)")
	}
	if _, err := Normalize([]Rule{{Name: "x", Enabled: true, Conditions: Conditions{Origins: []string{"browser"}},
		Requirement: Requirement{Approvals: 1}}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown origin accepted: %v", err)
	}
}

// Only a service account on the allowlist is exempt; the same id as a
// person, or another service account, is caught.
func TestRequesterConditions_TrustedServiceAccounts(t *testing.T) {
	r := mustRule(t, Conditions{MinIntensity: "active", TrustedServiceAccountIDs: []string{saTrusted}})
	f := Facts{IntensityTier: 2}
	f.Requester = &Requester{UserID: saTrusted, Origin: OriginServiceAccount, ServiceAccount: true}
	if r.Conditions.Matches(f) {
		t.Fatal("a trusted service account was caught")
	}
	f.Requester = &Requester{UserID: saTrusted, Origin: OriginUI}
	if !r.Conditions.Matches(f) {
		t.Fatal("a person with a trusted id was exempted")
	}
	f.Requester = &Requester{UserID: saOther, Origin: OriginServiceAccount, ServiceAccount: true}
	if !r.Conditions.Matches(f) {
		t.Fatal("an untrusted service account was exempted")
	}
	if _, err := Normalize([]Rule{{Name: "x", Enabled: true, Conditions: Conditions{TrustedServiceAccountIDs: []string{"svc-bot"}},
		Requirement: Requirement{Approvals: 1}}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a non-UUID trusted account accepted: %v", err)
	}
}

func TestRequesterConditions_RolesAndGroups(t *testing.T) {
	r := mustRule(t, Conditions{RequesterRoles: []string{"Member", roleCAB}})
	if !r.Conditions.Matches(Facts{Requester: &Requester{Origin: OriginUI, Roles: []string{"member"}}}) {
		t.Fatal("member not caught")
	}
	if !r.Conditions.Matches(Facts{Requester: &Requester{Origin: OriginUI, Roles: []string{"admin", roleCAB}}}) {
		t.Fatal("custom role id not caught")
	}
	if r.Conditions.Matches(Facts{Requester: &Requester{Origin: OriginUI, Roles: []string{"admin"}}}) {
		t.Fatal("admin caught by a member rule")
	}
	g := mustRule(t, Conditions{RequesterGroupIDs: []string{groupOps}})
	if g.Conditions.Matches(Facts{Requester: &Requester{Origin: OriginUI, GroupIDs: []string{saOther}}}) ||
		!g.Conditions.Matches(Facts{Requester: &Requester{Origin: OriginUI, GroupIDs: []string{groupOps}}}) {
		t.Fatal("group condition")
	}
	if _, err := Normalize([]Rule{{Name: "x", Enabled: true, Conditions: Conditions{RequesterRoles: []string{"superuser"}},
		Requirement: Requirement{Approvals: 1}}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown role name accepted: %v", err)
	}
}

func officeHours(match, tz string) Conditions {
	return Conditions{Hours: &Hours{Match: match, Timezone: tz, Windows: []Window{
		{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "09:00", End: "17:00"},
	}}}
}

// Business hours follow the wall clock across daylight-saving changes.
func TestHoursCondition_DST(t *testing.T) {
	r := mustRule(t, officeHours("", "America/New_York"))
	ny, _ := time.LoadLocation("America/New_York")
	cases := []struct {
		at   time.Time
		want bool // caught (outside hours)
	}{
		// Friday 6 March 2026, EST (UTC-5): 09:30 local = 14:30 UTC.
		{time.Date(2026, 3, 6, 14, 30, 0, 0, time.UTC), false},
		{time.Date(2026, 3, 6, 13, 30, 0, 0, time.UTC), true}, // 08:30 local
		// Monday 9 March 2026, EDT (UTC-4) after the change: 09:30 local = 13:30 UTC.
		{time.Date(2026, 3, 9, 13, 30, 0, 0, time.UTC), false},
		{time.Date(2026, 3, 9, 21, 30, 0, 0, time.UTC), true}, // 17:30 local
		// Sunday 8 March 2026 02:30 local does not exist; any instant that day is a weekend.
		{time.Date(2026, 3, 8, 15, 0, 0, 0, time.UTC), true},
		// Monday 2 November 2026, back to EST: 16:59 local = 21:59 UTC inside, 17:00 outside.
		{time.Date(2026, 11, 2, 21, 59, 0, 0, time.UTC), false},
		{time.Date(2026, 11, 2, 22, 0, 0, 0, time.UTC), true},
	}
	for _, c := range cases {
		if got := r.Conditions.Matches(Facts{At: c.at}); got != c.want {
			t.Errorf("%s (%s local): caught %v, want %v", c.at, c.at.In(ny).Format("Mon 15:04 MST"), got, c.want)
		}
	}
	in := mustRule(t, officeHours("inside", "America/New_York"))
	if !in.Conditions.Matches(Facts{At: time.Date(2026, 3, 9, 13, 30, 0, 0, time.UTC)}) {
		t.Error("inside: a run in office hours not caught")
	}
}

// Without a timezone in the condition the organization's is used; an
// unknown instant is caught.
func TestHoursCondition_OrganizationTimezoneAndFailClosed(t *testing.T) {
	r := mustRule(t, officeHours("outside", ""))
	at := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC) // Monday 10:00 in Ho Chi Minh City, 03:00 UTC
	if r.Conditions.Matches(Facts{At: at, Timezone: "Asia/Ho_Chi_Minh"}) {
		t.Fatal("10:00 in the organization's timezone is inside office hours")
	}
	if !r.Conditions.Matches(Facts{At: at}) {
		t.Fatal("03:00 UTC is outside office hours when the organization has no timezone")
	}
	if !r.Conditions.Matches(Facts{}) {
		t.Fatal("an unknown run time must be caught (fail closed)")
	}
	if !r.Conditions.Matches(Facts{At: at, Timezone: "Mars/Olympus"}) {
		t.Fatal("an unknown organization timezone must be caught (fail closed)")
	}
}

func TestHoursCondition_Validation(t *testing.T) {
	bad := []*Hours{
		{Windows: nil},
		{Match: "sometimes", Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}}},
		{Timezone: "Local", Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}}},
		{Windows: []Window{{Days: []string{"monday"}, Start: "09:00", End: "17:00"}}},
		{Windows: []Window{{Days: []string{"mon"}, Start: "17:00", End: "09:00"}}},
		{Windows: []Window{{Days: []string{"mon"}, Start: "24:00", End: "24:00"}}},
		{Windows: []Window{{Days: []string{"mon"}, Start: "9:00", End: "17:00"}}},
		{Windows: []Window{{Start: "09:00", End: "17:00"}}},
	}
	for i, h := range bad {
		if _, err := Normalize([]Rule{{Name: "x", Enabled: true, Conditions: Conditions{Hours: h}, Requirement: Requirement{Approvals: 1}}}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	ok := mustRule(t, Conditions{Hours: &Hours{Windows: []Window{{Days: []string{"Sat", "sun"}, Start: "00:00", End: "24:00"}}}})
	if ok.Conditions.Hours.Match != HoursOutside || ok.Conditions.Hours.Windows[0].Days[0] != "sat" {
		t.Fatalf("normalized %+v", ok.Conditions.Hours)
	}
}

func TestCallerContext(t *testing.T) {
	if _, ok := OriginFrom(context.Background()); ok {
		t.Fatal("empty context has an origin")
	}
	if o, ok := OriginFrom(WithOrigin(context.Background(), OriginAPIKey)); !ok || o != OriginAPIKey {
		t.Fatalf("origin %s", o)
	}
	if _, ok := OriginFrom(WithOrigin(context.Background(), "forged")); ok {
		t.Fatal("an unknown origin is not an origin")
	}
	if !NeedsRequester([]Rule{mustRule(t, Conditions{Origins: []string{"ui"}})}) || NeedsRequester([]Rule{mustRule(t, Conditions{MinIntensity: "active"})}) {
		t.Fatal("NeedsRequester")
	}
	if !NeedsClock([]Rule{mustRule(t, officeHours("", ""))}) {
		t.Fatal("NeedsClock")
	}
}
