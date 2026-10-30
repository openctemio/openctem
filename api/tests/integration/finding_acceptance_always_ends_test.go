package integration

// An accepted risk always ends: the database gives an accepted finding written
// without an end the default length (capped by its priority), keeps an end a
// writer set, and the CI gate does not honor an acceptance without an end.

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

func TestAcceptanceAlwaysEnds(t *testing.T) {
	f := newAcceptanceFixture(t)

	// A status write to accepted with no end gets the 90-day default.
	f.exec(t, `UPDATE findings SET status = 'accepted' WHERE id = $1`, f.findingID.String())
	status, end := f.state(t)
	if status != "accepted" || end == nil {
		t.Fatalf("accepted without an end: status=%s end=%v", status, end)
	}
	if d := time.Until(*end); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("default end = %v from now, want 90 days", d)
	}

	// An end a writer sets is kept, and a later write that clears it is refilled.
	set := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	f.exec(t, `UPDATE findings SET acceptance_expires_at = $2 WHERE id = $1`, f.findingID.String(), set)
	if _, end = f.state(t); end == nil || !end.Equal(set) {
		t.Fatalf("a set end was replaced: %v, want %v", end, set)
	}
	f.exec(t, `UPDATE findings SET acceptance_expires_at = NULL WHERE id = $1`, f.findingID.String())
	if _, end = f.state(t); end == nil {
		t.Fatal("an accepted finding lost its end")
	}

	// A KEV finding is capped at 30 days.
	f.exec(t, `UPDATE findings SET status = 'confirmed', is_in_kev = true WHERE id = $1`, f.findingID.String())
	f.exec(t, `UPDATE findings SET status = 'accepted' WHERE id = $1`, f.findingID.String())
	if _, end = f.state(t); end == nil || time.Until(*end) > 31*24*time.Hour {
		t.Fatalf("KEV acceptance end = %v, want at most 30 days", end)
	}

	// Leaving accepted still clears the end.
	f.exec(t, `UPDATE findings SET status = 'confirmed' WHERE id = $1`, f.findingID.String())
	if _, end = f.state(t); end != nil {
		t.Fatalf("a finding that left accepted kept its end: %v", end)
	}

	// An insert of an accepted finding without an end, in the other tenant,
	// gets its end too; the trigger touches only the row written.
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES (gen_random_uuid(), $1, 'acc-other', 'repository')`, f.other.String())
	f.exec(t, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		SELECT $1, id, 'sast', 'acc-tool', 'm', 'low', 'acc-other-fp', 'accepted' FROM assets WHERE tenant_id = $1`, f.other.String())
	var otherEnds, mine int
	if err := f.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'accepted' AND acceptance_expires_at IS NOT NULL`, f.other.String()).Scan(&otherEnds); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'accepted'`, f.tenant.String()).Scan(&mine); err != nil {
		t.Fatal(err)
	}
	if otherEnds != 1 || mine != 0 {
		t.Fatalf("other tenant ends=%d, own accepted=%d", otherEnds, mine)
	}

	// The gate never honors an acceptance without an end.
	if d := cirun.Decision(cirun.RunFinding{Status: "accepted"}, time.Now()); d != "" {
		t.Fatalf("gate honored an acceptance without an end: %q", d)
	}
}
