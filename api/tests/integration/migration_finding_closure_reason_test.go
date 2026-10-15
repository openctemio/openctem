package integration

// Migration finding_closure_reason: every closed finding gets a closure
// reason and (when resolved) a verification, mapped only from what
// resolution_method recorded and 'unknown' for everything else; the trigger
// keeps the pair consistent for every writer; the SQL rule function agrees with
// the Go tables; and up -> down -> up round-trips.

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

const closureMigTenant = "44444444-4444-4444-8444-444444444444"
const closureMigAsset = "55555555-5555-4555-8555-555555555555"

func TestMigrationFindingClosureReason_Backfill(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migclosure", dir)
	closure := testdb.MigrationVersion(t, dir, "finding_closure_reason")
	validate := testdb.MigrationVersion(t, dir, "finding_closure_reason_validate")
	testdb.Migrate(t, db, dir, validate, validate, true)
	testdb.Migrate(t, db, dir, closure, closure, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'c', 'mig-closure')`, closureMigTenant)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($2, $1, 'h', 'host')`, closureMigTenant, closureMigAsset)

	// fingerprint -> status, resolution_method, resolution, vex_justification
	type row struct{ status, method, resolution, vexJust string }
	rows := map[string]row{
		"scan":         {"resolved", "scan_verified", "", ""},
		"retest":       {"resolved", "retest_verified", "", ""},
		"review":       {"resolved", "security_reviewed", "", ""},
		"admin":        {"resolved", "admin_direct", "", ""},
		"mitigated":    {"resolved", "source_mitigated", "", ""},
		"vexfixed":     {"resolved", "vex_fixed", "", ""},
		"version":      {"resolved", "version_changed", "", ""},
		"retired":      {"resolved", "source_retired", "", ""},
		"license":      {"resolved", "license_policy", "", ""},
		"legacy":       {"resolved", "legacy", "", ""},
		"nomethod":     {"resolved", "", "Resolved via UI", ""},
		"vexna":        {"false_positive", "vex_not_affected", "", "component_not_present"},
		"vexna-nojust": {"false_positive", "vex_not_affected", "", ""},
		"advisory":     {"false_positive", "advisory_updated", "", ""},
		"fp":           {"false_positive", "", "not real", ""},
		"accepted":     {"accepted", "", "", ""},
		"dup":          {"duplicate", "", "duplicate", ""},
		"correlated":   {"duplicate", "", "correlated", ""},
		"open":         {"confirmed", "", "stale note", ""},
	}
	for fp := range rows {
		exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, 'sca', 't', 'm', 'high', $3, 'new')`, closureMigTenant, closureMigAsset, fp)
	}
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ('66666666-6666-4666-8666-666666666666', $1, $2, 'sca', 't', 'm', 'high', 'canon', 'new')`,
		closureMigTenant, closureMigAsset)
	for fp, r := range rows {
		exec(`UPDATE findings SET status = $2::text, resolution_method = NULLIF($3, ''), resolution = NULLIF($4, ''),
			vex_justification = NULLIF($5, ''),
			duplicate_of = CASE WHEN $2::text = 'duplicate' THEN '66666666-6666-4666-8666-666666666666'::uuid END
			WHERE tenant_id = $1 AND fingerprint = $6`, closureMigTenant, r.status, r.method, r.resolution, r.vexJust, fp)
	}

	want := map[string][2]string{ // fingerprint -> closure_reason, verification ("" = NULL)
		"scan": {"fixed", "covered_scan"}, "retest": {"fixed", "retest"}, "review": {"fixed", "security_review"},
		"admin": {"fixed", "attested"}, "mitigated": {"fixed", "source_reported"}, "vexfixed": {"fixed", "vex_statement"},
		"version": {"fixed", "source_reported"}, "retired": {"obsolete_source", "none"}, "license": {"obsolete_rule", "none"},
		// Nothing recorded: unknown, never a guessed reason.
		"legacy": {"unknown", "unknown"}, "nomethod": {"unknown", "unknown"},
		"vexna": {"component_not_present", "vex_statement"}, "vexna-nojust": {"unknown", "vex_statement"},
		"advisory": {"detection_error", "source_reported"}, "fp": {"unknown", ""},
		"accepted": {"unknown", ""}, "dup": {"duplicate", ""}, "correlated": {"correlated", ""},
		"open": {"", ""}, "canon": {"", ""},
	}
	check := func(round string) {
		t.Helper()
		for fp, w := range want {
			var reason, verified sql.NullString
			if err := db.QueryRow(`SELECT closure_reason, verification FROM findings WHERE fingerprint = $1`, fp).
				Scan(&reason, &verified); err != nil {
				t.Fatalf("%s: read %s: %v", round, fp, err)
			}
			if reason.String != w[0] || verified.String != w[1] {
				t.Errorf("%s: %s closure = %q / %q, want %q / %q", round, fp, reason.String, verified.String, w[0], w[1])
			}
		}
	}

	testdb.Migrate(t, db, dir, closure, validate, false)
	check("up")

	// resolution_method is gone.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'findings' AND column_name = 'resolution_method'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("resolution_method still there (%d, %v)", n, err)
	}

	// Down brings resolution_method back with what the closure recorded; up
	// again lands on the same closure.
	testdb.Migrate(t, db, dir, closure, validate, true)
	var method sql.NullString
	if err := db.QueryRow(`SELECT resolution_method FROM findings WHERE fingerprint = 'scan'`).Scan(&method); err != nil ||
		method.String != "scan_verified" {
		t.Fatalf("down: resolution_method = %v (%v), want scan_verified", method, err)
	}
	testdb.Migrate(t, db, dir, closure, validate, false)
	check("up again")
}

// The trigger keeps closure_reason / verification consistent with the
// status for every writer, and the CHECK refuses a reason of another status.
func TestFindingClosureTriggerAndCheck(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "closuretrg", dir)
	exec := func(q string, args ...any) error {
		_, err := db.Exec(q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'c', 'closure-trg')`, closureMigTenant)
	must(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($2, $1, 'h', 'host')`, closureMigTenant, closureMigAsset)
	must(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, 'sca', 't', 'm', 'high', 'f', 'new')`, closureMigTenant, closureMigAsset)
	read := func() (string, string) {
		t.Helper()
		var r, v sql.NullString
		if err := db.QueryRow(`SELECT closure_reason, verification FROM findings WHERE fingerprint = 'f'`).Scan(&r, &v); err != nil {
			t.Fatal(err)
		}
		return r.String, v.String
	}
	set := func(q string) {
		t.Helper()
		must(`UPDATE findings SET ` + q + ` WHERE fingerprint = 'f'`)
	}

	// A writer that names no closure gets the status default.
	set(`status = 'resolved'`)
	if r, v := read(); r != "unknown" || v != "unknown" {
		t.Fatalf("resolved with nothing named = %s / %s, want unknown / unknown", r, v)
	}
	// Reopening clears both, whatever the writer left.
	set(`status = 'confirmed'`)
	if r, v := read(); r != "" || v != "" {
		t.Fatalf("reopened = %s / %s, want none", r, v)
	}
	// A named closure is kept.
	set(`status = 'resolved', closure_reason = 'fixed', verification = 'retest'`)
	if r, v := read(); r != "fixed" || v != "retest" {
		t.Fatalf("resolved by retest = %s / %s", r, v)
	}
	// Moving to another closed status without a new reason drops the old one.
	set(`status = 'false_positive'`)
	if r, v := read(); r != "unknown" || v != "" {
		t.Fatalf("resolved -> false_positive = %s / %s, want unknown / none", r, v)
	}
	// A reason of another status is refused.
	if err := exec(`UPDATE findings SET closure_reason = 'fixed' WHERE fingerprint = 'f'`); err == nil {
		t.Fatal("false_positive with reason fixed was accepted")
	}
	// An obsolete resolve is verified by nothing.
	set(`status = 'confirmed'`)
	set(`status = 'resolved', closure_reason = 'obsolete_source'`)
	if r, v := read(); r != "obsolete_source" || v != "none" {
		t.Fatalf("obsolete resolve = %s / %s, want obsolete_source / none", r, v)
	}
	// An approval request names a reason of its own status only.
	if err := exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, justification, status, closure_reason)
		SELECT $1, id, 'accepted', 'j', 'pending', 'detection_error' FROM findings WHERE fingerprint = 'f'`, closureMigTenant); err == nil {
		t.Fatal("an accepted-risk request with a false-positive reason was accepted")
	}
}

// finding_closure_valid is the SQL copy of the Go closure tables: both agree
// on every status, reason and verification.
func TestFindingClosureValidMatchesGo(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database unreachable: %v", err)
	}

	reasons := []vulnerability.ClosureReason{vulnerability.ClosureReasonUnknown, "", "made_up"}
	for _, st := range vulnerability.AllFindingStatuses() {
		reasons = append(reasons, vulnerability.ClosureReasonsFor(st)...)
	}
	verifications := []vulnerability.Verification{"", "made_up",
		vulnerability.VerificationCoveredScan, vulnerability.VerificationRetest, vulnerability.VerificationSourceReported,
		vulnerability.VerificationVEXStatement, vulnerability.VerificationSecurityReview, vulnerability.VerificationAttested,
		vulnerability.VerificationNone, vulnerability.VerificationUnknown}
	for _, st := range vulnerability.AllFindingStatuses() {
		for _, r := range reasons {
			for _, v := range verifications {
				goOK := goClosureValid(st, r, v)
				var sqlOK bool
				if err := db.QueryRow(`SELECT finding_closure_valid($1, NULLIF($2, ''), NULLIF($3, ''))`,
					string(st), string(r), string(v)).Scan(&sqlOK); err != nil {
					t.Fatal(err)
				}
				if goOK != sqlOK {
					t.Errorf("status %s reason %q verification %q: Go %v, SQL %v", st, r, v, goOK, sqlOK)
				}
			}
		}
	}
}

// goClosureValid is the stored-row rule in Go terms: an open status has no
// closure; a closed one a reason of its own, and a verification exactly when
// resolved (optional on a false positive).
func goClosureValid(st vulnerability.FindingStatus, r vulnerability.ClosureReason, v vulnerability.Verification) bool {
	if !st.IsClosed() {
		return r == "" && v == ""
	}
	if r == "" || !r.ValidFor(st) {
		return false
	}
	switch st {
	case vulnerability.FindingStatusResolved:
		return v != "" && v.ValidFor(st)
	case vulnerability.FindingStatusFalsePositive:
		return v == "" || v.ValidFor(st)
	default:
		return v == ""
	}
}
