package integration

// A report's own fingerprint field is a hint, never the identity a stored
// finding is chosen by (RFC-043 §4, backend audit B7-D1). An uploader who
// knows (or guesses) the base an existing, triaged finding was keyed on must
// not move that triage onto a different issue on the same asset, and must not
// land a different issue on that finding as a re-sighting.

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// forgedBase is the base a finding written before the server decided identity
// was keyed on: the producer's own fingerprint.
const forgedBase = "0123456789abcdef0123456789abcdef"

func forgedRepoFile(tn v2Tenant) goldenFile {
	var f goldenFile
	f.Tool = "semgrep"
	f.Asset.Type = ctis.AssetTypeRepository
	f.Asset.Value = tn.repo
	return f
}

// legacyClientKeyed rewrites the only finding of the tenant into the shape a
// row written by the old ingest has: keyed on composite(asset, client
// fingerprint), version 1, triaged as a false positive.
func legacyClientKeyed(t *testing.T, g *goldenRig, tn v2Tenant) goldenRow {
	t.Helper()
	rows := g.rows(t, tn)
	if len(rows) != 1 {
		t.Fatalf("%d findings, want 1", len(rows))
	}
	row := rows[0]
	asset, err := shared.IDFromString(row.asset)
	if err != nil {
		t.Fatal(err)
	}
	legacy := vulnerability.CompositeFingerprint(asset.String(), forgedBase)
	if _, err := g.r.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 1, identity_key = NULL,
		status = 'false_positive', resolution = 'false_positive' WHERE id = $1`, row.id, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, row.id, legacy); err != nil {
		t.Fatal(err)
	}
	row.fingerprint, row.status = legacy, "false_positive"
	return row
}

func findRow(rows []goldenRow, id string) (goldenRow, bool) {
	for _, r := range rows {
		if r.id == id {
			return r, true
		}
	}
	return goldenRow{}, false
}

func TestDedupForgedFingerprint_DoesNotAdoptAnotherIssuesTriage(t *testing.T) {
	cases := map[string]struct{ triaged, forged ctis.Finding }{
		// Code finding (has a version-2 recipe): the forged key used to make
		// the triaged row be re-keyed to the new issue's version-2 key.
		"sast": {
			triaged: ctis.Finding{Type: ctis.FindingTypeVulnerability, RuleID: "rule.sql-injection", Title: "SQL injection",
				Severity: ctis.SeverityHigh, Fingerprint: forgedBase, Location: &ctis.FindingLocation{Path: "app/db.go", StartLine: 10}},
			forged: ctis.Finding{Type: ctis.FindingTypeVulnerability, RuleID: "rule.command-injection", Title: "Command injection",
				Severity: ctis.SeverityCritical, Fingerprint: forgedBase, Location: &ctis.FindingLocation{Path: "app/exec.go", StartLine: 99}},
		},
		// Compliance finding (keeps its version-1 key): the forged key used to
		// land the new issue on the triaged row as a re-sighting.
		"compliance": {
			triaged: ctis.Finding{Type: ctis.FindingTypeCompliance, RuleID: "cis-1.1", Title: "Password policy",
				Severity: ctis.SeverityMedium, Fingerprint: forgedBase},
			forged: ctis.Finding{Type: ctis.FindingTypeCompliance, RuleID: "cis-9.9", Title: "Audit logging disabled",
				Severity: ctis.SeverityHigh, Fingerprint: forgedBase},
		},
	}
	g := newGoldenRig(t)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tn := g.r.newTenant("semgrep")
			file := forgedRepoFile(tn)
			g.ingest(t, tn, file, file.Tool, c.triaged)
			triaged := legacyClientKeyed(t, g, tn)

			g.ingest(t, tn, file, file.Tool, c.forged)

			rows := g.rows(t, tn)
			got, ok := findRow(rows, triaged.id)
			if !ok {
				t.Fatal("the triaged finding is gone")
			}
			if got.fingerprint != triaged.fingerprint {
				t.Fatalf("the triaged finding was re-keyed to the forged report's issue (%s -> %s)", triaged.fingerprint, got.fingerprint)
			}
			if got.status != "false_positive" {
				t.Fatalf("triaged status = %s, want false_positive", got.status)
			}
			if len(rows) != 2 {
				t.Fatalf("%d findings, want 2: the forged report's issue must be a new finding", len(rows))
			}
			for _, r := range rows {
				if r.id != triaged.id && r.status != "new" {
					t.Fatalf("the new issue was born %s, want new", r.status)
				}
			}
		})
	}
}

// The same result as before, still carrying the producer's fingerprint the
// old row was keyed on, keeps its triage: the row is taken over because its
// asset, rule, tool and location match, not because of the fingerprint alone.
func TestDedupForgedFingerprint_LegacyClientKeyedRowKeepsItsTriage(t *testing.T) {
	cases := map[string]ctis.Finding{
		"sast": {Type: ctis.FindingTypeVulnerability, RuleID: "rule.sql-injection", Title: "SQL injection",
			Severity: ctis.SeverityHigh, Fingerprint: forgedBase, Location: &ctis.FindingLocation{Path: "app/db.go", StartLine: 10}},
		"compliance": {Type: ctis.FindingTypeCompliance, RuleID: "cis-1.1", Title: "Password policy",
			Severity: ctis.SeverityMedium, Fingerprint: forgedBase},
	}
	g := newGoldenRig(t)
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			tn := g.r.newTenant("semgrep")
			file := forgedRepoFile(tn)
			g.ingest(t, tn, file, file.Tool, f)
			triaged := legacyClientKeyed(t, g, tn)

			g.ingest(t, tn, file, file.Tool, f)

			rows := g.rows(t, tn)
			if len(rows) != 1 {
				t.Fatalf("%d findings, want 1 (a duplicate of the legacy row appeared)", len(rows))
			}
			got := rows[0]
			if got.id != triaged.id || got.status != "false_positive" {
				t.Fatalf("got %s/%s, want the legacy row %s still false_positive", got.id, got.status, triaged.id)
			}
			if got.fingerprint == triaged.fingerprint {
				t.Fatal("the legacy row kept the client-chosen key, want the server key")
			}
			if owner := aliasOwner(t, g.r.db, tn.tenant, triaged.fingerprint); owner != triaged.id {
				t.Fatalf("the legacy key belongs to %q, want %s", owner, triaged.id)
			}
		})
	}
}

// Two different secrets in one file that share a mask are two findings: the
// mask is not the secret (B7-D2). Without a keyed hash from the producer the
// key is anchored on rule, type and line as well.
func TestDedupSecrets_SameMaskDifferentSecretsAreTwoFindings(t *testing.T) {
	g := newGoldenRig(t)
	tn := g.r.newTenant("gitleaks")
	file := forgedRepoFile(tn)
	file.Tool = "gitleaks"
	secret := func(line int) ctis.Finding {
		return ctis.Finding{Type: ctis.FindingTypeSecret, RuleID: "aws-access-key", Title: "AWS access key",
			Severity: ctis.SeverityCritical, Location: &ctis.FindingLocation{Path: "deploy/.env", StartLine: line},
			Secret: &ctis.SecretDetails{SecretType: "api_key", MaskedValue: "AKIA****"}}
	}
	g.ingest(t, tn, file, file.Tool, secret(3))
	g.ingest(t, tn, file, file.Tool, secret(7))
	if rows := g.rows(t, tn); len(rows) != 2 {
		t.Fatalf("%d findings, want 2: two secrets with one mask were folded into one", len(rows))
	}
	// A re-scan of the same two secrets adds nothing.
	g.ingest(t, tn, file, file.Tool, secret(3))
	g.ingest(t, tn, file, file.Tool, secret(7))
	if rows := g.rows(t, tn); len(rows) != 2 {
		t.Fatalf("%d findings after a re-scan, want 2", len(rows))
	}
}

// A secret finding stored under the mask-only key of an older ingest keeps
// its triage when the same result arrives again.
func TestDedupSecrets_MaskOnlyKeyedRowKeepsItsTriage(t *testing.T) {
	g := newGoldenRig(t)
	tn := g.r.newTenant("gitleaks")
	file := forgedRepoFile(tn)
	file.Tool = "gitleaks"
	f := ctis.Finding{Type: ctis.FindingTypeSecret, RuleID: "aws-access-key", Title: "AWS access key",
		Severity: ctis.SeverityCritical, Location: &ctis.FindingLocation{Path: "deploy/.env", StartLine: 3},
		Secret: &ctis.SecretDetails{SecretType: "api_key", MaskedValue: "AKIA****"}}
	g.ingest(t, tn, file, file.Tool, f)
	rows := g.rows(t, tn)
	if len(rows) != 1 {
		t.Fatalf("%d findings, want 1", len(rows))
	}
	asset, err := shared.IDFromString(rows[0].asset)
	if err != nil {
		t.Fatal(err)
	}
	fp := vulnerability.NewSecretFingerprinter([]byte("golden-corpus-server-secret-0123456789"))
	old, ok := vulnerability.SecretIdentity(asset.String(), fp.Fingerprint(tn.tenant, "AKIA****"), "deploy/.env")
	if !ok {
		t.Fatal("no mask-only key")
	}
	if _, err := g.r.db.Exec(`UPDATE findings SET fingerprint = $2, status = 'false_positive', resolution = 'false_positive'
		WHERE id = $1`, rows[0].id, old.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	// A row written by the older ingest never had the newer key as an alias.
	if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, rows[0].id, old.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	g.ingest(t, tn, file, file.Tool, f)
	again := g.rows(t, tn)
	if len(again) != 1 || again[0].id != rows[0].id || again[0].status != "false_positive" {
		t.Fatalf("got %+v, want the mask-keyed row still false_positive and no duplicate", again)
	}
	if again[0].fingerprint == old.Fingerprint() {
		t.Fatal("the row kept the mask-only key")
	}
}
