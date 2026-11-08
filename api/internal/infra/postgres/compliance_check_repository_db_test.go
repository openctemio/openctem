package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func checkObs(asset shared.ID, control string, r compliancecheck.Result, at time.Time, actual string) compliancecheck.Observation {
	return compliancecheck.Observation{
		AssetID: asset, Fingerprint: "cc-" + asset.String() + "-" + control, BenchmarkKey: "cis-example-linux",
		BenchmarkName: "CIS Example Linux", BenchmarkVersion: "1.0.0", Framework: "cis", ControlID: control,
		ControlName: "Ensure " + control, Level: vulnerability.ComplianceLevel1, Result: r, ScannerSeverity: "high",
		Evidence: compliancecheck.Evidence{Actual: actual, Expected: "1"}, ToolName: "nessus", ObservedAt: at,
	}
}

type checkRow struct {
	id, result, evidenceActual string
	findingID                  sql.NullString
	lastChecked, lastChanged   time.Time
}

func readCheck(ctx context.Context, t *testing.T, db *sql.DB, tenant, asset shared.ID, control string) (checkRow, bool) {
	t.Helper()
	var c checkRow
	err := db.QueryRowContext(ctx, `SELECT id::text, result, COALESCE(evidence->>'actual', ''), finding_id::text,
			last_checked_at, last_changed_at
		FROM compliance_check_states WHERE tenant_id = $1 AND asset_id = $2 AND control_id = $3`,
		tenant.String(), asset.String(), control).Scan(&c.id, &c.result, &c.evidenceActual, &c.findingID, &c.lastChecked, &c.lastChanged)
	if errors.Is(err, sql.ErrNoRows) {
		return c, false
	}
	if err != nil {
		t.Fatalf("read check: %v", err)
	}
	return c, true
}

func historyResults(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, stateID string) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT result || ':' || COALESCE(previous_result, '-') FROM compliance_check_results
		WHERE tenant_id = $1 AND state_id = $2 ORDER BY observed_at, recorded_at`, tenant.String(), stateID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A control's state follows its newest result; every change, and the first
// observation, is history; an older observation is history only; the same
// observation twice changes nothing; the posture rollup counts the controls.
func TestComplianceCheckRecord_StateHistoryPosture_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewComplianceCheckRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", false)
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	// A failed check with its finding.
	f := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceVA, "nessus", vulnerability.FindingTypeCompliance)
	f.SetFingerprint("cc-" + host.String() + "-1.1")
	if err := NewFindingRepository(&DB{DB: db}).Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	st, err := repo.Record(ctx, tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{
		checkObs(host, "1.1", compliancecheck.ResultFail, t0, "0"),
		checkObs(host, "1.2", compliancecheck.ResultPass, t0, "1"),
		checkObs(host, "1.3", compliancecheck.ResultError, t0, ""),
		{AssetID: host, BenchmarkKey: "", ControlID: "x", Result: compliancecheck.ResultPass, ObservedAt: t0}, // invalid
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Created != 3 || st.Invalid != 1 || len(st.Assets) != 1 {
		t.Fatalf("stats = %+v", st)
	}
	c, ok := readCheck(ctx, t, db, tenant, host, "1.1")
	if !ok || c.result != "fail" || !c.findingID.Valid || c.findingID.String != f.ID().String() {
		t.Fatalf("1.1 state = %+v", c)
	}

	// The same file again: nothing changes.
	st, err = repo.Record(ctx, tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{checkObs(host, "1.1", compliancecheck.ResultFail, t0, "0")})
	if err != nil || st.Unchanged != 1 || st.Created+st.Changed != 0 {
		t.Fatalf("rerun stats = %+v, %v", st, err)
	}

	// A later pass: the state changes, the finding link stays, history grows.
	t1 := t0.Add(24 * time.Hour)
	if st, err = repo.Record(ctx, tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{checkObs(host, "1.1", compliancecheck.ResultPass, t1, "1")}); err != nil || st.Changed != 1 {
		t.Fatalf("pass stats = %+v, %v", st, err)
	}
	c, _ = readCheck(ctx, t, db, tenant, host, "1.1")
	if c.result != "pass" || c.evidenceActual != "1" || !c.lastChanged.Equal(t1) || !c.findingID.Valid {
		t.Fatalf("after pass = %+v", c)
	}

	// An older file arriving late: history only, the state keeps the pass.
	tOld := t0.Add(12 * time.Hour)
	if st, err = repo.Record(ctx, tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{checkObs(host, "1.1", compliancecheck.ResultFail, tOld, "0")}); err != nil || st.Older != 1 {
		t.Fatalf("older stats = %+v, %v", st, err)
	}
	c, _ = readCheck(ctx, t, db, tenant, host, "1.1")
	if c.result != "pass" || !c.lastChecked.Equal(t1) {
		t.Fatalf("older observation moved the state: %+v", c)
	}
	got := historyResults(ctx, t, db, tenant, c.id)
	want := []string{"fail:-", "fail:-", "pass:fail"}
	if len(got) != len(want) {
		t.Fatalf("history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("history = %v, want %v", got, want)
		}
	}

	// Same result, new evidence: a change.
	t2 := t1.Add(time.Hour)
	if st, _ = repo.Record(ctx, tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{checkObs(host, "1.1", compliancecheck.ResultPass, t2, "2")}); st.Changed != 1 {
		t.Fatalf("evidence change stats = %+v", st)
	}

	// Posture: the maintainer function counts the controls per result.
	if err := repo.RecomputePosture(ctx, tenant, []shared.ID{host}); err != nil {
		t.Fatal(err)
	}
	var pass, fail, errs, na int
	if err := db.QueryRowContext(ctx, `SELECT pass_count, fail_count, error_count, not_applicable_count FROM compliance_posture
		WHERE tenant_id = $1 AND asset_id = $2 AND benchmark_key = 'cis-example-linux'`, tenant.String(), host.String()).
		Scan(&pass, &fail, &errs, &na); err != nil {
		t.Fatal(err)
	}
	if pass != 2 || fail != 0 || errs != 1 || na != 0 {
		t.Fatalf("posture pass=%d fail=%d error=%d n/a=%d", pass, fail, errs, na)
	}
	var queued int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1 AND asset_id = $2 AND reasons & 32 = 32`,
		tenant.String(), host.String()).Scan(&queued); err != nil || queued == 0 {
		t.Fatalf("posture refresh not queued: %d, %v", queued, err)
	}
	// The maintainer consumes the mark and keeps the posture.
	if _, err := db.ExecContext(ctx, `SELECT * FROM dash_process_dirty($1, 5000)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
}

// Another tenant's asset is never written and another tenant's finding is
// never linked, even with a matching fingerprint.
func TestComplianceCheckRecord_TenantPinned_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewComplianceCheckRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	hostA := seedPracticeAsset(ctx, t, db, tenantA, "host", false)
	hostB := seedPracticeAsset(ctx, t, db, tenantB, "host", false)
	t0 := time.Now().UTC().Truncate(time.Second)

	// Tenant B's finding carries the fingerprint tenant A reports.
	fb := newPracticeFinding(t, tenantB, hostB, vulnerability.FindingSourceVA, "nessus", vulnerability.FindingTypeCompliance)
	fb.SetFingerprint("cc-" + hostA.String() + "-9.9")
	if err := NewFindingRepository(&DB{DB: db}).Create(ctx, fb); err != nil {
		t.Fatal(err)
	}

	st, err := repo.Record(ctx, tenantA, compliancecheck.SourceIngest, []compliancecheck.Observation{
		checkObs(hostA, "9.9", compliancecheck.ResultFail, t0, "0"),
		checkObs(hostB, "9.9", compliancecheck.ResultFail, t0, "0"), // another tenant's asset
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Created != 1 || st.Invalid != 1 {
		t.Fatalf("stats = %+v", st)
	}
	c, ok := readCheck(ctx, t, db, tenantA, hostA, "9.9")
	if !ok || c.findingID.Valid {
		t.Fatalf("tenant A state links a finding of tenant B: %+v", c)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM compliance_check_states WHERE asset_id = $1`, hostB.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenant B asset written by tenant A: %d, %v", n, err)
	}
}

// A compliance finding's remediation key reads its benchmark control from
// its check state: one control group across assets.
func TestComplianceCheck_RemediationKeySource_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	host := seedPracticeAsset(ctx, t, db, tenant, "host", false)
	f := newPracticeFinding(t, tenant, host, vulnerability.FindingSourceVA, "nessus", vulnerability.FindingTypeCompliance)
	f.SetFingerprint("cc-" + host.String() + "-2.1")
	if err := NewFindingRepository(&DB{DB: db}).Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	if _, err := NewComplianceCheckRepository(&DB{DB: db}).Record(ctx, tenant, compliancecheck.SourceIngest,
		[]compliancecheck.Observation{checkObs(host, "2.1", compliancecheck.ResultFail, time.Now().UTC(), "0")}); err != nil {
		t.Fatal(err)
	}
	srcs, err := NewFindingRemediationKeyRepository(&DB{DB: db}).KeySources(ctx, tenant, []shared.ID{f.ID()})
	if err != nil || len(srcs) != 1 {
		t.Fatalf("key sources = %v, %v", srcs, err)
	}
	in := srcs[0].Input
	if in.BenchmarkKey != "cis-example-linux" || in.ControlID != "2.1" || in.BenchmarkName != "CIS Example Linux" {
		t.Fatalf("key input = %+v", in)
	}
	// Another tenant reading the same finding id gets nothing.
	other := seedTestTenant(ctx, t, db)
	if srcs, err := NewFindingRemediationKeyRepository(&DB{DB: db}).KeySources(ctx, other, []shared.ID{f.ID()}); err != nil || len(srcs) != 0 {
		t.Fatalf("cross-tenant key sources = %v, %v", srcs, err)
	}
}

// Merging an asset into another keeps every control state the kept asset
// lacks and the whole history of both, and drops the merged posture rows.
func TestComplianceCheck_AssetMergeKeepsHistory_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewComplianceCheckRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	keep := seedPracticeAsset(ctx, t, db, tenant, "host", false)
	merged := seedPracticeAsset(ctx, t, db, tenant, "host", false)
	t0 := time.Now().UTC().Truncate(time.Second)
	if _, err := repo.Record(ctx, tenant, compliancecheck.SourceIngest, []compliancecheck.Observation{
		checkObs(keep, "1.1", compliancecheck.ResultPass, t0, "1"),
		checkObs(merged, "1.1", compliancecheck.ResultFail, t0, "0"),
		checkObs(merged, "1.2", compliancecheck.ResultFail, t0, "0"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecomputePosture(ctx, tenant, []shared.ID{keep, merged}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mergeAssetReferences(ctx, tx, tenant.String(), shared.NewID().String(), keep.String(), []string{merged.String()}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		var n int
		if err := db.QueryRowContext(ctx, q, tenant.String(), keep.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM compliance_check_states WHERE tenant_id = $1 AND asset_id = $2`); n != 2 {
		t.Fatalf("kept asset has %d states, want 2", n)
	}
	if c, _ := readCheck(ctx, t, db, tenant, keep, "1.1"); c.result != "pass" {
		t.Fatalf("the kept asset's own state did not win: %+v", c)
	}
	if n := count(`SELECT count(*) FROM compliance_check_results WHERE tenant_id = $1 AND asset_id = $2`); n != 3 {
		t.Fatalf("kept asset has %d history rows, want 3 (nothing lost)", n)
	}
	if n := count(`SELECT count(*) FROM compliance_posture WHERE tenant_id = $1 AND asset_id <> $2`); n != 0 {
		t.Fatalf("%d posture rows of the merged asset remain", n)
	}
}
