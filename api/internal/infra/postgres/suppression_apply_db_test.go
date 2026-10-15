package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

// Approving a suppression rule closes the open findings it matches, with the
// same matcher ingest uses, and lifting the rule (expiry, delete) reopens
// them. Findings already decided, from people, of other assets or of other
// tenants are never touched.

type openFindingSeed struct {
	asset  shared.ID
	source string
	tool   string
	rule   string
	path   string
	status string
}

func seedOpenFinding(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, s openFindingSeed) shared.ID {
	t.Helper()
	id := shared.NewID()
	if s.source == "" {
		s.source = "sast"
	}
	if s.tool == "" {
		s.tool = "semgrep"
	}
	if s.status == "" {
		s.status = "new"
	}
	var path any
	if s.path != "" {
		path = s.path
	}
	var resolvedAt any
	switch s.status {
	case "resolved", "false_positive", "accepted", "duplicate":
		resolvedAt = time.Now()
	}
	// A duplicate names its canonical finding: a resolved one, which no
	// suppression rule touches.
	var dupOf any
	if s.status == "duplicate" {
		dupOf = seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: s.asset, status: "resolved"}).String()
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, file_path, message, severity, fingerprint, status, resolved_at, duplicate_of)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'msg', 'high', $8, $9, $10, $11)`,
		id.String(), tenant.String(), s.asset.String(), s.source, s.tool, s.rule, path,
		"fp-"+id.String(), s.status, resolvedAt, dupOf); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

// newPendingRule stores a pending rule and returns it as the approver loads
// it (updated_at at database precision), already approved in memory.
func newPendingRule(ctx context.Context, t *testing.T, repo *SuppressionRepository, tenant, requester, approver shared.ID,
	typ suppression.SuppressionType, configure func(*suppression.Rule),
) (*suppression.Rule, time.Time) {
	t.Helper()
	rule, err := suppression.NewRule(tenant, "rule", typ, requester)
	if err != nil {
		t.Fatal(err)
	}
	configure(rule)
	if err := repo.Save(ctx, rule); err != nil {
		t.Fatal(err)
	}
	loaded, err := repo.FindByID(ctx, tenant, rule.ID())
	if err != nil {
		t.Fatal(err)
	}
	reviewed := loaded.UpdatedAt()
	if err := loaded.Approve(approver); err != nil {
		t.Fatal(err)
	}
	return loaded, reviewed
}

func assertStatus(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID, wantStatus, wantResolution, label string) {
	t.Helper()
	status, resolution := findingState(ctx, t, db, id)
	if status != wantStatus || resolution != wantResolution {
		t.Errorf("%s: status=%s resolution=%q, want %s %q", label, status, resolution, wantStatus, wantResolution)
	}
}

func suppCount(ctx context.Context, t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSuppressionApprove_ClosesMatchingOpenFindings_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "supp.apply.req")
	approver := seedGroupsUser(ctx, t, db, "supp.apply.appr")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	other := seedOwnedAsset(ctx, t, db, tenant, nil)

	rule, reviewed := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeFalsePositive, func(r *suppression.Rule) {
		r.SetToolName("Semgrep") // tool match is case-insensitive
		r.SetRuleIDPattern("py_sqli*")
		r.SetPathPattern("src/**/*.py")
	})

	match := func(status string) openFindingSeed {
		return openFindingSeed{asset: asset, rule: "py_sqli.raw", path: "src/app/db.py", status: status}
	}
	closed := []shared.ID{
		seedOpenFinding(ctx, t, db, tenant, match("new")),
		seedOpenFinding(ctx, t, db, tenant, match("confirmed")),
		seedOpenFinding(ctx, t, db, tenant, match("in_progress")),
		seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: other, rule: "py_sqli.fmt", path: "src/x.py", status: "fix_applied"}),
	}
	untouched := map[string]shared.ID{
		"already accepted":       seedOpenFinding(ctx, t, db, tenant, match("accepted")),
		"already false positive": seedOpenFinding(ctx, t, db, tenant, match("false_positive")),
		"resolved":               seedOpenFinding(ctx, t, db, tenant, match("resolved")),
		"duplicate":              seedOpenFinding(ctx, t, db, tenant, match("duplicate")),
		"pentest source":         seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, source: "pentest", rule: "py_sqli.raw", path: "src/app/db.py"}),
		"manual source":          seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, source: "manual", rule: "py_sqli.raw", path: "src/app/db.py"}),
		"path outside glob":      seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "py_sqli.raw", path: "test/db.py"}),
		"no path":                seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "py_sqli.raw"}),
		"underscore is literal":  seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "pyXsqli.raw", path: "src/app/db.py"}),
		"other tool":             seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, tool: "bandit", rule: "py_sqli.raw", path: "src/app/db.py"}),
	}
	// Another tenant's finding the rule's criteria would match.
	otherTenant := seedTestTenant(ctx, t, db)
	otherTenantAsset := seedOwnedAsset(ctx, t, db, otherTenant, nil)
	foreign := seedOpenFinding(ctx, t, db, otherTenant, openFindingSeed{asset: otherTenantAsset, rule: "py_sqli.raw", path: "src/app/db.py"})

	n, err := repo.CountMatchingOpenFindings(ctx, rule, suppression.MaxFindingsAppliedOnApprove)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(closed) {
		t.Fatalf("preview = %d, want %d", n, len(closed))
	}

	res, err := repo.Approve(ctx, rule, reviewed, approver, map[string]any{"note": "x"}, suppression.MaxFindingsAppliedOnApprove)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != n || res.Capped {
		t.Fatalf("approve = %+v, want %d applied (the preview count), not capped", res, n)
	}

	for _, id := range closed {
		assertStatus(ctx, t, db, id, "false_positive", "suppressed", "matching open finding")
	}
	for label, id := range untouched {
		status, resolution := findingState(ctx, t, db, id)
		if resolution == "suppressed" {
			t.Errorf("%s: suppressed (status %s), want untouched", label, status)
		}
	}
	assertStatus(ctx, t, db, foreign, "new", "", "other tenant's finding")

	if got := suppCount(ctx, t, db, `SELECT COUNT(*) FROM finding_suppressions WHERE suppression_rule_id = $1 AND applied_by = 'approval'`, rule.ID().String()); got != len(closed) {
		t.Errorf("links = %d, want %d", got, len(closed))
	}
	if got := suppCount(ctx, t, db, `SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND activity_type = 'status_changed'
		AND actor_id = $2 AND changes->>'suppression_rule_id' = $3 AND changes->>'new_status' = 'false_positive' AND changes ? 'old_status'`,
		tenant.String(), approver.String(), rule.ID().String()); got != len(closed) {
		t.Errorf("activities = %d, want %d", got, len(closed))
	}
	var details []byte
	if err := db.QueryRowContext(ctx, `SELECT details FROM suppression_rule_audit WHERE suppression_rule_id = $1 AND action = 'approved'`,
		rule.ID().String()).Scan(&details); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(details, &d)
	if d["applied_findings"] != float64(len(closed)) || d["capped"] != false || d["note"] != "x" {
		t.Errorf("audit details = %v", d)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM suppression_rules WHERE id = $1`, rule.ID().String()).Scan(&status); err != nil || status != "approved" {
		t.Fatalf("rule status = %q, %v", status, err)
	}

	// The rule expires: what the approval closed comes back.
	if _, err := db.ExecContext(ctx, `UPDATE suppression_rules SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, rule.ID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ExpireRules(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range closed {
		assertStatus(ctx, t, db, id, "new", "", "lifted after expiry")
	}
	assertStatus(ctx, t, db, untouched["already accepted"], "accepted", "", "accepted before the rule")
}

func TestSuppressionApprove_AssetBoundAcceptedRisk_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "supp.asset.req")
	approver := seedGroupsUser(ctx, t, db, "supp.asset.appr")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	other := seedOwnedAsset(ctx, t, db, tenant, nil)

	rule, reviewed := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeAcceptedRisk, func(r *suppression.Rule) {
		r.SetRuleIDPattern("CVE-2024-0001")
		r.SetAssetID(&asset)
	})
	hit := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, tool: "trivy", rule: "CVE-2024-0001"})
	otherAsset := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: other, tool: "trivy", rule: "CVE-2024-0001"})
	inProgress := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, tool: "trivy", rule: "CVE-2024-0001", status: "in_progress"})
	prefixOnly := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, tool: "trivy", rule: "CVE-2024-00012"})

	res, err := repo.Approve(ctx, rule, reviewed, approver, nil, suppression.MaxFindingsAppliedOnApprove)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 1 {
		t.Fatalf("applied = %d, want 1", res.Applied)
	}
	assertStatus(ctx, t, db, hit, "accepted", "suppressed", "finding on the rule's asset")
	assertStatus(ctx, t, db, otherAsset, "new", "", "finding on another asset")
	// An accepted-risk rule does not overrule work in progress.
	assertStatus(ctx, t, db, inProgress, "in_progress", "", "finding in progress")
	assertStatus(ctx, t, db, prefixOnly, "new", "", "exact rule id")

	if err := repo.Delete(ctx, tenant, rule.ID()); err != nil {
		t.Fatal(err)
	}
	assertStatus(ctx, t, db, hit, "new", "", "lifted after delete")
}

func TestSuppressionApprove_CapAndReviewedVersion_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "supp.cap.req")
	approver := seedGroupsUser(ctx, t, db, "supp.cap.appr")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	rule, reviewed := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeFalsePositive, func(r *suppression.Rule) {
		r.SetRuleIDPattern("go.noisy")
	})
	for range 5 {
		seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "go.noisy"})
	}
	// Small pages, so the candidate scan and the update cross page bounds.
	prevPage := suppressionApplyPage
	suppressionApplyPage = 2
	t.Cleanup(func() { suppressionApplyPage = prevPage })

	if n, err := repo.CountMatchingOpenFindings(ctx, rule, 3); err != nil || n != 4 {
		t.Fatalf("count with limit 3 = %d, %v; want 4 (limit+1)", n, err)
	}

	// A version other than the stored one is refused and changes nothing.
	if _, err := repo.Approve(ctx, rule, reviewed.Add(-time.Second), approver, nil, 3); !errors.Is(err, suppression.ErrRuleChangedSinceReview) {
		t.Fatalf("stale version err = %v, want ErrRuleChangedSinceReview", err)
	}
	if got := suppCount(ctx, t, db, `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND status = 'false_positive'`, tenant.String()); got != 0 {
		t.Fatalf("refused approval closed %d findings", got)
	}

	res, err := repo.Approve(ctx, rule, reviewed, approver, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 3 || !res.Capped {
		t.Fatalf("approve = %+v, want 3 applied and capped", res)
	}
	if got := suppCount(ctx, t, db, `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND status = 'false_positive' AND resolution = 'suppressed'`, tenant.String()); got != 3 {
		t.Fatalf("closed = %d, want 3", got)
	}

	// The rule is no longer pending: a second approval is refused.
	if _, err := repo.Approve(ctx, rule, rule.UpdatedAt(), approver, nil, 3); !errors.Is(err, suppression.ErrRuleNotPending) {
		t.Fatalf("second approval err = %v, want ErrRuleNotPending", err)
	}
}
