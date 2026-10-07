package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A secret scanner's report that repeats the raw secret outside the snippet
// (title, description, message, tags, properties, remediation, masked
// value) is ingested through the real service on a migrated database, once
// applied and once held in the result quarantine. Afterwards no column of
// any row the tenant owns, in any table the app role can read, holds the
// raw secret. The fake credentials are assembled at run time so that no
// secret scanner flags this repository.
func TestIngest_RawSecretStoredNowhere(t *testing.T) {
	ctx := context.Background()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("betterleaks")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetResultQuarantine(postgres.NewSensorResultRepository(db), sensorresult.DefaultLimits())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	token := "ghp_" + "9fK2xLq7RzT4mWv8Np3Yb6Hc"
	key := "AKIA" + "Q3EGRZ7X2MNVBP4L"
	report := func(id string) *ctis.Report {
		return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "betterleaks", Capabilities: []string{"secret"}},
			Metadata: ctis.ReportMetadata{ID: id, Timestamp: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: tn.repo}},
			Findings: []ctis.Finding{
				{
					// A producer that masked nothing.
					Type: ctis.FindingTypeSecret, Severity: ctis.SeverityHigh, RuleID: "github-pat", AssetRef: "repo",
					Title:       "GitHub token " + token + " in ci.yml",
					Description: "token " + token, Message: "found " + token,
					Location:    &ctis.FindingLocation{Path: "ci.yml", StartLine: 4, Snippet: "token: " + token},
					Secret:      &ctis.SecretDetails{SecretType: "token", MaskedValue: token},
					Remediation: &ctis.Remediation{Recommendation: "revoke " + token},
					Tags:        []string{"secret", token},
					Properties:  ctis.Properties{"commit_message": "add " + token},
				},
				{
					// A converter that did not recognize the tool typed it
					// "vulnerability"; it is a secret by its tool.
					Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityCritical, RuleID: "aws-access-token", AssetRef: "repo",
					Title:    "aws-access-token " + key,
					Location: &ctis.FindingLocation{Path: "config.py", StartLine: 2, Snippet: key},
				},
			}}
	}

	// Applied.
	out, err := svc.Ingest(ctx, agt, ingest.Input{Report: report("rep-applied"), Options: ingest.Options{Admitted: true, Route: "ctis"}})
	if err != nil || len(out.Errors) > 0 || out.FindingsCreated != 2 {
		t.Fatalf("Ingest: %v %v created=%d", err, out.Errors, out.FindingsCreated)
	}
	var title string
	if err := r.db.QueryRowContext(ctx, `SELECT title FROM findings WHERE tenant_id = $1 AND rule_id = 'github-pat'`, tid.String()).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(title, "ghp_********") {
		t.Errorf("title = %q, want the masked token", title)
	}

	// Held in the quarantine (no command, tenant in quarantine mode): the
	// stored report is masked too.
	_, err = svc.Ingest(ctx, agt, ingest.Input{Report: report("rep-held"), Options: ingest.Options{Route: "ctis"}})
	var qe *ingest.QuarantinedError
	if !asQuarantined(err, &qe) {
		t.Fatalf("unsolicited report: err = %v, want it quarantined", err)
	}

	// Every table with a tenant_id the app role may read: no row of this
	// tenant holds either raw secret in any column.
	tables := tenantTables(t, r)
	if len(tables) < 10 {
		t.Fatalf("only %d tenant tables readable: %v", len(tables), tables)
	}
	checked := map[string]int{}
	for _, table := range tables {
		// row_to_json shows a bytea column (a stored report payload) as
		// hex; add each one decoded, so a JSON payload is searched as text.
		text := "row_to_json(x)::text"
		for _, col := range byteaColumns(t, r, table) {
			text += " || coalesce(encode(x." + pq.QuoteIdentifier(col) + ", 'escape'), '')"
		}
		q := fmt.Sprintf(`SELECT count(*), count(*) FILTER (WHERE strpos(%[1]s, $2) > 0 OR strpos(%[1]s, $3) > 0)
			FROM public.%[2]s x WHERE tenant_id = $1`, text, pq.QuoteIdentifier(table))
		var total, leaks int
		if err := r.db.QueryRowContext(ctx, q, tid.String(), token, key).Scan(&total, &leaks); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if leaks > 0 {
			t.Errorf("%s: %d row(s) hold a raw secret", table, leaks)
		}
		checked[table] = total
	}
	if checked["findings"] != 2 || checked["sensor_result_quarantine"] != 1 {
		t.Fatalf("rows checked: findings=%d quarantine=%d, want 2 and 1", checked["findings"], checked["sensor_result_quarantine"])
	}
}

func byteaColumns(t *testing.T, r *v2Rig, table string) []string {
	t.Helper()
	rows, err := r.db.QueryContext(context.Background(), `SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND data_type = 'bytea' ORDER BY column_name`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func asQuarantined(err error, target **ingest.QuarantinedError) bool {
	return errors.As(err, target)
}

// tenantTables lists the base tables with a tenant_id column that the
// connected role may read.
func tenantTables(t *testing.T, r *v2Rig) []string {
	t.Helper()
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT cl.relname FROM pg_class cl
		JOIN pg_namespace n ON n.oid = cl.relnamespace
		JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		WHERE n.nspname = 'public' AND cl.relkind IN ('r', 'p') AND NOT cl.relispartition
		  AND has_table_privilege(cl.oid, 'SELECT')
		ORDER BY cl.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
