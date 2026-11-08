package postgres

// Finding source records (docs/architecture/finding-source-records.md): a
// second source's values survive for every field family, one row per
// finding and source, the newest observation of a source wins, the cap,
// tenant isolation, merges and erasure.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/tools/findingsourcebackfill"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func (f *receiptFixture) findingRepo() *FindingRepository {
	return NewFindingRepository(&DB{DB: f.db})
}

func (f *receiptFixture) findingByTool(tenant, asset shared.ID, fp, tool string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, fingerprint, status, title) VALUES ($1, $2, $3, 'va', $4, 'm', 'high', $5, 'new', 't')`,
		id.String(), tenant.String(), asset.String(), tool, fp); err != nil {
		f.t.Fatalf("seed finding %s: %v", fp, err)
	}
	return id
}

func (f *receiptFixture) upsertSources(tenant shared.ID, src vulnerability.SourceIdentity, vals ...vulnerability.SourceRecordValues) int64 {
	f.t.Helper()
	n, err := f.findingRepo().UpsertSourceRecords(f.ctx, tenant, src, vals)
	if err != nil {
		f.t.Fatalf("upsert source records: %v", err)
	}
	return n
}

func (f *receiptFixture) sources(tenant, finding shared.ID) []vulnerability.SourceRecord {
	f.t.Helper()
	recs, err := f.findingRepo().ListSourceRecords(f.ctx, tenant, finding)
	if err != nil {
		f.t.Fatalf("list source records: %v", err)
	}
	return recs
}

func f64(v float64) *float64 { return &v }

// sourceValues is a full record of one source: every field family set.
func sourceValues(fp, tag string, at time.Time) vulnerability.SourceRecordValues {
	return vulnerability.SourceRecordValues{
		Fingerprint: fp, ObservedAt: at, ToolVersion: "v-" + tag,
		Title: "title " + tag, Description: "description " + tag, Snippet: "snippet " + tag,
		Recommendation: "recommendation " + tag, Message: "message " + tag,
		Severity: "high", CVSSScore: f64(8.1), CVSSVector: "CVSS:3.1/AV:N/" + tag,
		TypeDetails: json.RawMessage(`{"kind":"` + tag + `"}`),
		Interop: vulnerability.InteropData{
			Native: &vulnerability.InteropNative{Scheme: "nessus_plugin", VulnID: "id-" + tag, Family: "family " + tag,
				Severity: "vendor " + tag, Status: "open"},
			Solution:         &vulnerability.InteropSolution{Type: "patch"},
			Scores:           []vulnerability.InteropScore{{System: "cvss", Version: "3.1", Value: f64(8.1), Source: tag}},
			VulnerabilityIDs: []vulnerability.InteropVulnID{{Type: "cve", ID: "CVE-2024-6387"}, {Type: "vendor", ID: "v-" + tag}},
			SourceExtra:      map[string]string{"plugin_output": "output " + tag},
			LocationKey:      "host:22/" + tag,
		},
	}
}

func checkSourceValues(t *testing.T, r vulnerability.SourceRecord, tag string) {
	t.Helper()
	v := r.Values
	want := map[string][2]string{
		"text":            {v.Title + "|" + v.Description + "|" + v.Snippet + "|" + v.Recommendation + "|" + v.Message, fmt.Sprintf("title %[1]s|description %[1]s|snippet %[1]s|recommendation %[1]s|message %[1]s", tag)},
		"rating":          {fmt.Sprintf("%s|%v|%s", v.Severity, v.CVSSScore != nil && *v.CVSSScore == 8.1, v.CVSSVector), "high|true|CVSS:3.1/AV:N/" + tag},
		"tool_version":    {v.ToolVersion, "v-" + tag},
		"type_details":    {strings.ReplaceAll(string(v.TypeDetails), " ", ""), `{"kind":"` + tag + `"}`},
		"native":          {fmt.Sprintf("%v", v.Interop.Native != nil && v.Interop.Native.VulnID == "id-"+tag && v.Interop.Native.Family == "family "+tag && v.Interop.Native.Severity == "vendor "+tag && v.Interop.Native.Scheme == "nessus_plugin"), "true"},
		"solution":        {fmt.Sprintf("%v", v.Interop.Solution != nil && v.Interop.Solution.Type == "patch"), "true"},
		"scores":          {fmt.Sprintf("%v", len(v.Interop.Scores) == 1 && v.Interop.Scores[0].Source == tag), "true"},
		"vulnerabilities": {fmt.Sprintf("%v", len(v.Interop.VulnerabilityIDs) == 2 && v.Interop.VulnerabilityIDs[1].ID == "v-"+tag), "true"},
		"source_extra":    {v.Interop.SourceExtra["plugin_output"], "output " + tag},
		"location_key":    {v.Interop.LocationKey, "host:22/" + tag},
	}
	for family, p := range want {
		if p[0] != p[1] {
			t.Errorf("source %s, %s: got %q, want %q", r.Tool, family, p[0], p[1])
		}
	}
}

// The owner rule: a second source reporting the same finding never
// overwrites the first one's values, for every field family; each keeps its
// own record, the first reporter's tool is the primary one.
func TestFindingSourceRecords_SecondSourceSurvives_DB(t *testing.T) {
	f := newReceiptFixture(t)
	sensor := f.sensor(f.tenant)
	finding := f.findingByTool(f.tenant, f.asset, "fp-two-sources", "nessus")
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"},
		sourceValues("fp-two-sources", "nessus", t0))
	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "scan", SensorID: &sensor, IsSensor: true, Tool: "openvas"},
		sourceValues("fp-two-sources", "openvas", t0.Add(time.Minute)))

	recs := f.sources(f.tenant, finding)
	if len(recs) != 2 {
		t.Fatalf("%d records, want 2", len(recs))
	}
	if recs[0].Tool != "nessus" || !recs[0].Primary || recs[1].Tool != "openvas" || recs[1].Primary {
		t.Fatalf("order/primary: %s %v, %s %v", recs[0].Tool, recs[0].Primary, recs[1].Tool, recs[1].Primary)
	}
	checkSourceValues(t, recs[0], "nessus")
	checkSourceValues(t, recs[1], "openvas")
	if recs[1].SensorID == nil || *recs[1].SensorID != sensor || recs[1].Channel != "scan" {
		t.Errorf("sensor source = %+v", recs[1])
	}
	if !recs[0].FirstSeenAt.Equal(t0) {
		t.Errorf("first seen %v, want %v", recs[0].FirstSeenAt, t0)
	}

	// The second source again, with other values: only its own record moves.
	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "scan", SensorID: &sensor, IsSensor: true, Tool: "openvas"},
		sourceValues("fp-two-sources", "openvas2", t0.Add(2*time.Minute)))
	recs = f.sources(f.tenant, finding)
	if len(recs) != 2 {
		t.Fatalf("%d records after a repeat, want 2", len(recs))
	}
	checkSourceValues(t, recs[0], "nessus")
	if recs[1].Values.Title != "title openvas2" || !recs[1].FirstSeenAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("repeat: title %q first seen %v", recs[1].Values.Title, recs[1].FirstSeenAt)
	}

	// An older observation of a source moves first seen only; empty values
	// never erase.
	older := vulnerability.SourceRecordValues{Fingerprint: "fp-two-sources", ObservedAt: t0.Add(-time.Hour), Title: "stale"}
	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"}, older)
	newer := vulnerability.SourceRecordValues{Fingerprint: "fp-two-sources", ObservedAt: t0.Add(time.Hour), Title: "title nessus"}
	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"}, newer)
	recs = f.sources(f.tenant, finding)
	checkSourceValues(t, recs[0], "nessus")
	if !recs[0].FirstSeenAt.Equal(t0.Add(-time.Hour)) || !recs[0].LastSeenAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("times after old and new files: %v .. %v", recs[0].FirstSeenAt, recs[0].LastSeenAt)
	}

	// Differences: vendor severity, native id, family, title differ.
	diffs := vulnerability.SourceRecordDifferences(recs)
	fields := map[string]bool{}
	for _, d := range diffs {
		fields[d.Field] = true
	}
	for _, want := range []string{"vendor_severity", "native_id", "family", "title"} {
		if !fields[want] {
			t.Errorf("difference %s not reported: %+v", want, diffs)
		}
	}
	if fields["severity"] {
		t.Error("equal severities reported as a difference")
	}
}

// Another tenant's finding with the same fingerprint is never written, and
// its id is not found; another tenant's sensor id is stored as the shared
// platform sender without the id.
func TestFindingSourceRecords_TenantIsolation_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)
	mine := f.findingByTool(f.tenant, f.asset, "fp-iso", "nessus")
	theirs := f.findingByTool(other, otherAsset, "fp-iso", "nessus")
	theirSensor := f.sensor(other)

	n := f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "scan", SensorID: &theirSensor, IsSensor: true, Tool: "nessus"},
		sourceValues("fp-iso", "a", time.Now()))
	if n != 1 {
		t.Fatalf("wrote %d rows, want 1", n)
	}
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE tenant_id = $1`, other.String()); c != 0 {
		t.Errorf("another tenant got %d records", c)
	}
	recs := f.sources(f.tenant, mine)
	if len(recs) != 1 || recs[0].SensorID != nil || recs[0].Sender != "platform" {
		t.Fatalf("foreign sensor stored as %+v", recs)
	}
	if _, err := f.findingRepo().ListSourceRecords(f.ctx, f.tenant, theirs); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("another tenant's finding: err %v, want not found", err)
	}
	// The composite key refuses a row naming another tenant's finding.
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO finding_source_records (tenant_id, finding_id, channel, tool, first_seen_at, last_seen_at)
		VALUES ($1, $2, 'upload', 'x', now(), now())`, f.tenant.String(), theirs.String()); err == nil {
		t.Error("a record pointing at another tenant's finding was accepted")
	}
	// Organization erasure removes the tenant's records.
	f.upsertSources(other, vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"}, sourceValues("fp-iso", "b", time.Now()))
	if _, err := f.db.ExecContext(f.ctx, `DELETE FROM tenants WHERE id = $1`, other.String()); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE tenant_id = $1`, other.String()); c != 0 {
		t.Errorf("%d records left after tenant erasure", c)
	}
}

// At most MaxSourceRecordsPerFinding sources per finding; an existing
// source still updates past the cap. A finding with no record reads empty.
func TestFindingSourceRecords_Cap_DB(t *testing.T) {
	f := newReceiptFixture(t)
	finding := f.findingByTool(f.tenant, f.asset, "fp-cap", "t0")
	if got := f.sources(f.tenant, finding); len(got) != 0 {
		t.Fatalf("new finding has %d records", len(got))
	}
	for i := range vulnerability.MaxSourceRecordsPerFinding + 3 {
		f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "upload", Tool: fmt.Sprintf("t%d", i)},
			vulnerability.SourceRecordValues{Fingerprint: "fp-cap", Title: "x"})
	}
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE finding_id = $1`, finding.String()); c != vulnerability.MaxSourceRecordsPerFinding {
		t.Fatalf("%d records, want the cap %d", c, vulnerability.MaxSourceRecordsPerFinding)
	}
	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "upload", Tool: "t1"},
		vulnerability.SourceRecordValues{Fingerprint: "fp-cap", Title: "updated"})
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE finding_id = $1 AND tool = 't1' AND title = 'updated'`, finding.String()); c != 1 {
		t.Error("an existing source did not update past the cap")
	}
}

// A merge of duplicate findings carries the loser's records to the
// survivor; a source both have is folded into one row that keeps both
// time ranges and fills what the newer record left empty.
func TestFindingSourceRecords_MergeCarriesRecords_DB(t *testing.T) {
	f := newReceiptFixture(t)
	survivor := f.findingByTool(f.tenant, f.asset, "fp-keep", "nessus")
	loser := f.findingByTool(f.tenant, f.asset, "fp-dup", "openvas")
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	nessus := vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"}
	f.upsertSources(f.tenant, nessus, vulnerability.SourceRecordValues{Fingerprint: "fp-keep", ObservedAt: t0.Add(time.Minute), Title: "survivor title"})
	f.upsertSources(f.tenant, nessus, vulnerability.SourceRecordValues{Fingerprint: "fp-dup", ObservedAt: t0, Title: "old title", Recommendation: "loser recommendation"})
	f.upsertSources(f.tenant, vulnerability.SourceIdentity{Channel: "connector", Sender: "tenablesc", Tool: "openvas"},
		sourceValues("fp-dup", "openvas", t0))

	if err := f.findingRepo().MarkDuplicateOf(f.ctx, f.tenant, loser, survivor, ""); err != nil {
		t.Fatalf("mark duplicate: %v", err)
	}
	recs := f.sources(f.tenant, survivor)
	if len(recs) != 2 {
		t.Fatalf("survivor has %d records, want 2", len(recs))
	}
	var folded, moved *vulnerability.SourceRecord
	for i := range recs {
		switch recs[i].Tool {
		case "nessus":
			folded = &recs[i]
		case "openvas":
			moved = &recs[i]
		}
	}
	if folded == nil || moved == nil {
		t.Fatalf("records %+v", recs)
	}
	if folded.Values.Title != "survivor title" || folded.Values.Recommendation != "loser recommendation" ||
		!folded.FirstSeenAt.Equal(t0) || !folded.LastSeenAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("folded record: %+v", folded)
	}
	checkSourceValues(t, *moved, "openvas")
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE finding_id = $1`, loser.String()); c != 0 {
		t.Errorf("%d records left on the tombstone", c)
	}
}

// The backfill: a dry run counts and writes nothing; -apply gives each
// finding with a sighting one backfilled record from the finding row,
// attributed to its most recent sighting; a finding without a sighting gets
// none; a re-run writes nothing; -tenant touches only that tenant.
func TestFindingSourceBackfill_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)
	withSighting := f.findingByTool(f.tenant, f.asset, "fp-bf-1", "nessus")
	noSighting := f.findingByTool(f.tenant, f.asset, "fp-bf-2", "nessus")
	theirs := f.findingByTool(other, otherAsset, "fp-bf-3", "nessus")
	if _, err := f.db.ExecContext(f.ctx, `UPDATE findings SET description = $2, title = 'row title', native_vuln_id = '201194',
		source_meta = '{"native":{"vuln_id":"201194","severity":"3"}}', source_extra = '{"plugin_type":"remote"}',
		remediation = '{"recommendation":"Upgrade."}'
		WHERE id = ANY($1::uuid[])`, pq.Array([]string{withSighting.String(), theirs.String()}), strings.Repeat("d", vulnerability.MaxSourceDescription+100)); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	for _, s := range []struct {
		tenant, finding shared.ID
		channel, tool   string
		last            time.Time
	}{
		{f.tenant, withSighting, "upload", "nessus", t0},
		{f.tenant, withSighting, "connector", "tenablesc", t0.Add(time.Hour)},
		{other, theirs, "upload", "nessus", t0},
	} {
		if _, err := f.db.ExecContext(f.ctx, `INSERT INTO finding_sightings (tenant_id, finding_id, channel, tool, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $5)`, s.tenant.String(), s.finding.String(), s.channel, s.tool, s.last); err != nil {
			t.Fatal(err)
		}
	}

	dry, err := findingsourcebackfill.Run(f.ctx, f.db, findingsourcebackfill.Options{Tenant: &f.tenant})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Missing != 2 || dry.WithSighting != 1 || dry.NoSighting != 1 || dry.ByChannel["connector"] != 1 || dry.Written != 0 {
		t.Errorf("dry run = %+v", dry)
	}
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE tenant_id = $1`, f.tenant.String()); c != 0 {
		t.Fatalf("dry run wrote %d records", c)
	}

	got, err := findingsourcebackfill.Run(f.ctx, f.db, findingsourcebackfill.Options{Tenant: &f.tenant, Apply: true, Batch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got.Written != 1 || got.Batches != 2 {
		t.Errorf("apply = %+v", got)
	}
	recs := f.sources(f.tenant, withSighting)
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	r := recs[0]
	if r.Channel != "connector" || r.Tool != "tenablesc" || !r.Backfilled || !r.Values.Truncated ||
		r.Values.Title != "row title" || len(r.Values.Description) != vulnerability.MaxSourceDescription ||
		r.Values.Recommendation != "Upgrade." || r.Values.Interop.Native == nil || r.Values.Interop.Native.Severity != "3" ||
		r.Values.Interop.Native.VulnID != "201194" || r.Values.Interop.SourceExtra["plugin_type"] != "remote" {
		t.Errorf("backfilled record = %+v", r)
	}
	if len(f.sources(f.tenant, noSighting)) != 0 {
		t.Error("a finding without a sighting got a record")
	}
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE tenant_id = $1`, other.String()); c != 0 {
		t.Errorf("a -tenant run wrote %d records of another tenant", c)
	}
	again, err := findingsourcebackfill.Run(f.ctx, f.db, findingsourcebackfill.Options{Tenant: &f.tenant, Apply: true})
	if err != nil || again.Written != 0 {
		t.Errorf("re-run = %+v %v", again, err)
	}
}
