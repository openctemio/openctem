package integration

// Same-issue links across tools at ingest: two SAST engines that flag one
// line with the same weakness, and one secret value found in several files
// and repositories, are linked without being merged (each finding keeps its
// status); the false-link cases from the use-case catalog stay apart; the
// dashboard facts count a group once; the backfill finds the same links.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type linkRig struct {
	r    *v2Rig
	repo *postgres.FindingIssueLinkRepository
}

func newLinkRig(t *testing.T, wired bool) *linkRig {
	t.Helper()
	lr := &linkRig{}
	lr.r = newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		lr.repo = postgres.NewFindingIssueLinkRepository(db)
		if wired {
			svc.SetIssueLinkStore(lr.repo)
		}
		svc.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("issue-links-server-secret-0123456789")))
	})
	return lr
}

func (l *linkRig) scan(t *testing.T, tn v2Tenant, tool, repo string, fs ...ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	for i := range fs {
		fs[i].AssetRef = "a"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: "github.com/acme/" + repo + "-" + tn.tenant.String()[:8]}},
		Findings: fs}
	if out, err := l.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil || len(out.Errors) > 0 {
		t.Fatalf("ingest %s: %v %+v", tool, err, out)
	}
}

func sastAt(rule, path string, start, end int, snippet string, cwes ...string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "SQL injection", Severity: ctis.SeverityHigh, RuleID: rule,
		Location:      &ctis.FindingLocation{Path: path, StartLine: start, EndLine: end, Snippet: snippet},
		Vulnerability: &ctis.VulnerabilityDetails{CWEIDs: cwes}}
}

func secretAt(path, raw string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeSecret, Title: "AWS key", Severity: ctis.SeverityHigh, RuleID: "aws-access-key",
		Location: &ctis.FindingLocation{Path: path, StartLine: 3},
		Secret:   &ctis.SecretDetails{SecretType: "aws", MaskedValue: raw}}
}

func (l *linkRig) idOf(t *testing.T, tn v2Tenant, rule, path string) string {
	t.Helper()
	var id string
	if err := l.r.db.QueryRowContext(context.Background(), `SELECT f.id FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.rule_id = $2 AND f.file_path = $3 AND f.status <> 'duplicate' ORDER BY a.name LIMIT 1`,
		tn.tenant.String(), rule, path).Scan(&id); err != nil {
		t.Fatalf("finding %s %s: %v", rule, path, err)
	}
	return id
}

func (l *linkRig) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := l.r.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (l *linkRig) linked(t *testing.T, tn v2Tenant, a, b string) bool {
	t.Helper()
	return l.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active'
		AND ((primary_id = $2 AND member_id = $3) OR (primary_id = $3 AND member_id = $2))`, tn.tenant.String(), a, b) == 1
}

func TestIssueLinks_SASTTwoEnginesSameLineSameWeakness(t *testing.T) {
	l := newLinkRig(t, true)
	tn := l.r.newTenant("semgrep", "codeql")
	code := `cursor.execute("SELECT * FROM users WHERE id = " + uid)`
	l.scan(t, tn, "semgrep", "shop",
		sastAt("python.django.security.injection.sql", "app/views.py", 42, 42, code, "CWE-89"),
		sastAt("python.lang.security.audit.xss", "app/views.py", 42, 42, code, "CWE-79"),
		sastAt("python.django.security.injection.sql", "app/models.py", 10, 10, "q = raw(x)", "CWE-89"))
	if _, err := l.r.db.Exec(`UPDATE findings SET status = 'confirmed' WHERE tenant_id = $1 AND rule_id = 'python.django.security.injection.sql'`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	l.scan(t, tn, "codeql", "shop",
		sastAt("py/sql-injection", "app/views.py", 40, 45, "", "cwe-089"),
		sastAt("py/sql-injection", "app/models.py", 30, 31, "", "CWE-89"))

	semgrepSQL := l.idOf(t, tn, "python.django.security.injection.sql", "app/views.py")
	codeqlSQL := l.idOf(t, tn, "py/sql-injection", "app/views.py")
	xss := l.idOf(t, tn, "python.lang.security.audit.xss", "app/views.py")
	if !l.linked(t, tn, semgrepSQL, codeqlSQL) {
		t.Fatal("two engines on one line with one weakness are not linked")
	}
	// The earlier finding is the primary; neither status changed.
	if l.count(t, `SELECT count(*) FROM finding_issue_links WHERE primary_id = $1 AND member_id = $2 AND rule = 'sast_overlap'
		AND basis = '{asset,path,line_range,cwe}'`, semgrepSQL, codeqlSQL) != 1 {
		t.Fatal("primary is not the earlier finding, or the basis is wrong")
	}
	if l.count(t, `SELECT count(*) FROM findings WHERE id = $1 AND status = 'confirmed'`, semgrepSQL) != 1 ||
		l.count(t, `SELECT count(*) FROM findings WHERE id = $1 AND status = 'new' AND duplicate_of IS NULL`, codeqlSQL) != 1 {
		t.Fatal("a link changed a finding's status")
	}
	// False links: another weakness on the same line; the same weakness on
	// disjoint lines of another file.
	if l.linked(t, tn, xss, codeqlSQL) {
		t.Fatal("XSS and SQL injection on one line were linked")
	}
	if l.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1`, tn.tenant.String()) != 1 {
		t.Fatal("findings on disjoint lines were linked")
	}
	if l.count(t, `SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'issue_linked'`, codeqlSQL) != 1 {
		t.Fatal("no timeline entry on the member")
	}

	// The dashboard facts count the group once.
	var asset string
	if err := l.r.db.QueryRow(`SELECT asset_id FROM findings WHERE id = $1`, semgrepSQL).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	if _, err := l.r.db.Exec(`SELECT dash_recompute_asset($1, $2)`, tn.tenant.String(), asset); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := l.r.db.QueryRow(`SELECT COALESCE(sum(finding_count), 0) FROM dash_asset_state WHERE tenant_id = $1 AND asset_id = $2`,
		tn.tenant.String(), asset).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if total := l.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2`, tn.tenant.String(), asset); stored != total-1 {
		t.Fatalf("facts count %d of %d findings, want the group counted once (%d)", stored, total, total-1)
	}
}

func TestIssueLinks_SASTSamePathOnAnotherAssetIsNotLinked(t *testing.T) {
	l := newLinkRig(t, true)
	tn := l.r.newTenant("semgrep", "codeql")
	l.scan(t, tn, "semgrep", "svc-a", sastAt("python.django.security.injection.sql", "app/views.py", 42, 42, "x", "CWE-89"))
	l.scan(t, tn, "codeql", "svc-b", sastAt("py/sql-injection", "app/views.py", 42, 42, "", "CWE-89"))
	if n := l.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1`, tn.tenant.String()); n != 0 {
		t.Fatalf("linked across assets (monorepo split): %d", n)
	}
}

func TestIssueLinks_SecretSameValueAcrossFilesAndRepositories(t *testing.T) {
	l := newLinkRig(t, true)
	tn := l.r.newTenant("betterleaks", "trivy")
	raw := "AKIAQ3EXAMPLEKEY7781"
	l.scan(t, tn, "betterleaks", "api", secretAt("config.go", raw), secretAt("deploy/env", raw), secretAt("other.go", "AKIAQ3DIFFERENT00001"))
	l.scan(t, tn, "trivy", "web", secretAt("settings.py", raw))
	// A producer that sends only a mask: never linked (masks are shared).
	l.scan(t, tn, "trivy", "api", secretAt("masked.go", "AKIA****************"))

	a := l.idOf(t, tn, "aws-access-key", "config.go")
	b := l.idOf(t, tn, "aws-access-key", "deploy/env")
	c := l.idOf(t, tn, "aws-access-key", "settings.py")
	other := l.idOf(t, tn, "aws-access-key", "other.go")
	masked := l.idOf(t, tn, "aws-access-key", "masked.go")
	if !l.linked(t, tn, a, b) && !l.linked(t, tn, b, a) {
		t.Fatal("one secret in two files is not linked")
	}
	if l.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active' AND rule = 'secret_value'`, tn.tenant.String()) != 2 {
		t.Fatal("want one group of three (two links)")
	}
	if l.count(t, `SELECT count(*) FROM finding_issue_links WHERE member_id = $1 OR primary_id = $1`, c) != 1 {
		t.Fatal("the same secret in another repository is not in the group")
	}
	for _, id := range []string{other, masked} {
		if l.count(t, `SELECT count(*) FROM finding_issue_links WHERE member_id = $1 OR primary_id = $1`, id) != 0 {
			t.Fatalf("finding %s (another value, or a mask) was linked", id)
		}
	}
	// No link key is a value a person could read back.
	if l.count(t, `SELECT count(*) FROM finding_link_keys WHERE key LIKE '%EXAMPLE%'`) != 0 {
		t.Fatal("a link key contains the secret")
	}
}

func TestIssueLinks_UnlinkedPairStaysApartAndBackfillMatchesIngest(t *testing.T) {
	// Ingest without links, then the backfill: same groups as ingest.
	l := newLinkRig(t, false)
	tn := l.r.newTenant("semgrep", "codeql")
	l.scan(t, tn, "semgrep", "shop", sastAt("python.django.security.injection.sql", "app/views.py", 42, 42, "x", "CWE-89"))
	l.scan(t, tn, "codeql", "shop", sastAt("py/sql-injection", "app/views.py", 42, 43, "", "CWE-89"))
	if n := l.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1`, tn.tenant.String()); n != 0 {
		t.Fatalf("links without the store: %d", n)
	}
	ctx := context.Background()
	dry, err := l.repo.BackfillLinks(ctx, tn.tenant, false, 1)
	if err != nil || dry.Linked != 1 {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
	if n := l.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1`, tn.tenant.String()); n != 0 {
		t.Fatal("the dry run wrote links")
	}
	rep, err := l.repo.BackfillLinks(ctx, tn.tenant, true, 1)
	if err != nil || rep.Linked != 1 {
		t.Fatalf("apply: %+v %v", rep, err)
	}
	again, err := l.repo.BackfillLinks(ctx, tn.tenant, true, 1)
	if err != nil || again.Linked != 0 {
		t.Fatalf("second run is not idempotent: %+v %v", again, err)
	}
	a := l.idOf(t, tn, "python.django.security.injection.sql", "app/views.py")
	b := l.idOf(t, tn, "py/sql-injection", "app/views.py")
	aID, _ := shared.IDFromString(a)
	bID, _ := shared.IDFromString(b)
	if _, _, err := l.repo.Unlink(ctx, tn.tenant, aID, bID, ""); err != nil {
		t.Fatal(err)
	}
	if again, err := l.repo.BackfillLinks(ctx, tn.tenant, true, 1); err != nil || again.Linked != 0 {
		t.Fatalf("relinked an unlinked pair: %+v %v", again, err)
	}
	// Another tenant's identical findings never join this tenant's group.
	tn2 := l.r.newTenant("semgrep", "codeql")
	l.scan(t, tn2, "semgrep", "shop", sastAt("python.django.security.injection.sql", "app/views.py", 42, 42, "x", "CWE-89"))
	if _, err := l.repo.BackfillLinks(ctx, tn2.tenant, true, 1); err != nil {
		t.Fatal(err)
	}
	if n := l.count(t, `SELECT count(*) FROM finding_issue_links l JOIN findings f ON f.id IN (l.primary_id, l.member_id)
		WHERE f.tenant_id <> l.tenant_id`); n != 0 {
		t.Fatalf("cross-tenant link rows: %d", n)
	}
}
