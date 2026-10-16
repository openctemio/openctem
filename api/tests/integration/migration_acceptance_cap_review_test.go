package integration

// Migration acceptance_cap_review: an acceptance that already runs longer
// than its priority's cap is flagged for review with a timeline entry and is
// never shortened; one inside the cap is left alone. The SQL cap is the Go
// cap.

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestMigrationAcceptanceCapReview(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migcap", dir)
	mig := testdb.MigrationVersion(t, dir, "acceptance_cap_review")
	validate := testdb.MigrationVersion(t, dir, "acceptance_cap_review_validate")

	for _, pc := range []string{"", "P0", "P1", "P2", "P3"} {
		for _, kev := range []bool{false, true} {
			var days int
			if err := db.QueryRow(`SELECT finding_max_acceptance_days(NULLIF($1, ''), $2)`, pc, kev).Scan(&days); err != nil {
				t.Fatal(err)
			}
			if want := int(vulnerability.MaxAcceptanceFor(pc, kev) / (24 * time.Hour)); days != want {
				t.Errorf("cap(%q, kev=%v) SQL %d, Go %d", pc, kev, days, want)
			}
		}
	}

	testdb.Migrate(t, db, dir, mig, validate, true)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const tenant = "aaaaaaaa-1111-4111-8111-111111111111"
	const asset = "aaaaaaaa-2222-4222-8222-222222222222"
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'cap', 'mig-cap')`, tenant)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($2, $1, 'h', 'host')`, tenant, asset)
	seed := func(fp, pc string, kev bool, days int) {
		t.Helper()
		exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
			priority_class, is_in_kev, resolved_at, acceptance_expires_at)
			VALUES ($1, $2, 'sca', 't', 'm', 'high', $3, 'accepted', NULLIF($4, ''), $5, NOW(), NOW() + make_interval(days => $6))`,
			tenant, asset, fp, pc, kev, days)
	}
	seed("p0-60", "P0", false, 60)   // over 30
	seed("kev-29", "P3", true, 29)   // inside 30
	seed("p2-100", "P2", false, 100) // inside 180
	seed("p3-400", "P3", false, 400) // over 365
	seed("none-200", "", false, 200) // inside 365

	testdb.Migrate(t, db, dir, mig, validate, false)

	flagged := map[string]bool{}
	rows, err := db.Query(`SELECT f.fingerprint FROM finding_decision_reviews r JOIN findings f ON f.id = r.finding_id
		WHERE r.reason = 'acceptance_exceeds_cap' AND r.cleared_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			t.Fatal(err)
		}
		flagged[fp] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(flagged) != 2 || !flagged["p0-60"] || !flagged["p3-400"] {
		t.Errorf("flagged %v, want p0-60 and p3-400", flagged)
	}
	// Never shortened: the over-cap end stands; a timeline entry says why.
	var stillOver bool
	if err := db.QueryRow(`SELECT acceptance_expires_at > NOW() + interval '59 days' FROM findings WHERE fingerprint = 'p0-60'`).Scan(&stillOver); err != nil || !stillOver {
		t.Errorf("p0-60 acceptance end changed (%v)", err)
	}
	var entries int
	if err := db.QueryRow(`SELECT count(*) FROM finding_activities WHERE activity_type = 'decision_review'
		AND changes->>'reason' = 'acceptance_exceeds_cap'`).Scan(&entries); err != nil || entries != 2 {
		t.Errorf("timeline entries = %d (%v), want 2", entries, err)
	}
	// Running it again flags nothing new (one open flag per finding).
	testdb.Migrate(t, db, dir, mig, validate, true)
	testdb.Migrate(t, db, dir, mig, validate, false)
	var open int
	if err := db.QueryRow(`SELECT count(*) FROM finding_decision_reviews WHERE reason = 'acceptance_exceeds_cap' AND cleared_at IS NULL`).Scan(&open); err != nil || open != 2 {
		t.Errorf("open flags after a re-run = %d (%v), want 2", open, err)
	}
}
