package integration

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A change to any classifier input queues the asset of the open finding for
// the finding-priority worker at once, instead of waiting for the daily
// reconcile: the finding's CVE, CVSS, exposure flags, data exposure and
// compliance impact, the asset's CIA ratings, and the asset's owners. A write
// that leaves the value unchanged, or a closed finding, queues nothing.
func TestPriorityQueue_InputChangesQueueTheAsset(t *testing.T) {
	db := setupTestDB(t)
	tenant := createTestTenant(t, db, "prio-triggers")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		_ = db.Close()
	})
	user := shared.NewID()
	mustExecPQ(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'owner')`, user.String(), user.String()+"@example.com")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, user.String()) })

	asset := shared.NewID()
	mustExecPQ(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'prio-host', 'host')`, asset.String(), tenant.String())
	open := shared.NewID()
	mustExecPQ(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cvss_score, cve_id)
		VALUES ($1, $2, $3, 'sast', 'prio-tool', 'm', 'medium', 'prio-open', 'confirmed', 5.0, 'CVE-2030-0001')`,
		open.String(), tenant.String(), asset.String())

	queued := func() bool {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM finding_priority_queue WHERE asset_id = $1 AND tenant_id = $2`,
			asset.String(), tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	drain := func() { mustExecPQ(t, db, `DELETE FROM finding_priority_queue WHERE asset_id = $1`, asset.String()) }
	drain() // the insert queued it

	// A write that does not change a watched value queues nothing.
	for _, q := range []string{
		`UPDATE findings SET cvss_score = 5.0, cve_id = 'CVE-2030-0001', is_internet_accessible = is_internet_accessible,
			compliance_impact = compliance_impact WHERE id = $1`,
		`UPDATE findings SET message = 'other text' WHERE id = $1`,
	} {
		mustExecPQ(t, db, q, open.String())
		if queued() {
			t.Errorf("an unchanged input queued the asset: %s", q)
		}
	}

	changes := []struct{ name, q string }{
		{"cvss_score", `UPDATE findings SET cvss_score = 9.8 WHERE id = $1`},
		{"cve_id", `UPDATE findings SET cve_id = 'CVE-2030-0002' WHERE id = $1`},
		{"is_internet_accessible", `UPDATE findings SET is_internet_accessible = true WHERE id = $1`},
		{"is_network_accessible", `UPDATE findings SET is_network_accessible = true WHERE id = $1`},
		{"exposure_vector", `UPDATE findings SET exposure_vector = 'network' WHERE id = $1`},
		{"data_exposure_risk", `UPDATE findings SET data_exposure_risk = 'high' WHERE id = $1`},
		{"compliance_impact", `UPDATE findings SET compliance_impact = ARRAY['pci_dss'] WHERE id = $1`},
	}
	for _, c := range changes {
		drain()
		mustExecPQ(t, db, c.q, open.String())
		if !queued() {
			t.Errorf("a change of findings.%s did not queue the asset", c.name)
		}
	}

	// The catalog link: a finding gaining its vulnerability row.
	drain()
	vuln := shared.NewID()
	mustExecPQ(t, db, `INSERT INTO vulnerabilities (id, cve_id, title, severity) VALUES ($1, 'CVE-2030-0002', 't', 'high')`, vuln.String())
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM findings WHERE vulnerability_id = $1`, vuln.String())
		_, _ = db.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vuln.String())
	})
	mustExecPQ(t, db, `UPDATE findings SET vulnerability_id = $2 WHERE id = $1`, open.String(), vuln.String())
	if !queued() {
		t.Error("a change of findings.vulnerability_id did not queue the asset")
	}

	// A closed finding is not queued by a change of its inputs.
	closed := shared.NewID()
	mustExecPQ(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cvss_score)
		VALUES ($1, $2, $3, 'sast', 'prio-tool', 'm', 'medium', 'prio-closed', 'resolved', 5.0)`,
		closed.String(), tenant.String(), asset.String())
	drain()
	mustExecPQ(t, db, `UPDATE findings SET cvss_score = 9.9 WHERE id = $1`, closed.String())
	if queued() {
		t.Error("a closed finding's input change queued the asset")
	}

	// Asset CIA ratings.
	for _, col := range []string{"impact_confidentiality", "impact_integrity", "impact_availability"} {
		drain()
		mustExecPQ(t, db, `UPDATE assets SET `+col+` = 'high' WHERE id = $1`, asset.String())
		if !queued() {
			t.Errorf("a change of assets.%s did not queue the asset", col)
		}
	}
	drain()
	mustExecPQ(t, db, `UPDATE assets SET impact_integrity = 'high' WHERE id = $1`, asset.String())
	if queued() {
		t.Error("an unchanged CIA rating queued the asset")
	}

	// Owners: add, move and remove.
	drain()
	mustExecPQ(t, db, `INSERT INTO asset_owners (asset_id, user_id) VALUES ($1, $2)`, asset.String(), user.String())
	if !queued() {
		t.Error("adding an owner did not queue the asset")
	}
	drain()
	other := shared.NewID()
	mustExecPQ(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'prio-host-2', 'host')`, other.String(), tenant.String())
	mustExecPQ(t, db, `UPDATE asset_owners SET asset_id = $2 WHERE asset_id = $1`, asset.String(), other.String())
	if !queued() {
		t.Error("moving an owner away did not queue the asset it left")
	}
	mustExecPQ(t, db, `UPDATE asset_owners SET asset_id = $1 WHERE asset_id = $2`, asset.String(), other.String())
	drain()
	mustExecPQ(t, db, `DELETE FROM asset_owners WHERE asset_id = $1`, asset.String())
	if !queued() {
		t.Error("removing an owner did not queue the asset")
	}

	// An asset with no open finding is not queued by an owner change; another
	// organization's assets are never touched.
	mustExecPQ(t, db, `DELETE FROM findings WHERE asset_id = $1`, asset.String())
	drain()
	mustExecPQ(t, db, `INSERT INTO asset_owners (asset_id, user_id) VALUES ($1, $2)`, asset.String(), user.String())
	if queued() {
		t.Error("an owner change queued an asset with no open finding")
	}
}

func mustExecPQ(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%v: %s", err, q)
	}
}
