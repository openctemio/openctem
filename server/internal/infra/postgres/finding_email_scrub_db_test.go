package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PRIVACY (research/292): the scrub masks the addresses left in one tenant's
// tool-reported findings (descriptive columns only, jsonb values only) and
// evidence items; a dry run writes nothing; identifiers, human-reported
// findings, unreadable items and other tenants stay; a second run changes
// nothing.
func TestScrubStoredEmails_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)

	addressed := func(tid, aid shared.ID, source string) string {
		id := seedOpenFinding(ctx, t, db, tid, openFindingSeed{asset: aid, source: source, tool: "nuclei", rule: "r@example.com", path: "dir/jane@example.com.txt"}).String()
		if _, err := db.ExecContext(ctx, `UPDATE findings SET
			title = 'Contact Jane.Doe@Example.COM', message = 'GET /?u=jane%40example.com',
			description = 'Staff: ops@example.org, lib@1.2.3, image@sha256:abc', snippet = 'mail = "a.b@example.net"',
			context_snippet = 'x@example.com', attack_prerequisites = 'phish jane@example.com',
			misconfig_expected = 'owner@example.com', misconfig_actual = 'none', scanner_output = '[x] bob@example.net',
			tags = ARRAY['owner:ops@example.org', 'lib@1.2.3', NULL],
			remediation = '{"recommendation": "mail sec@example.com", "steps": ["x"]}',
			metadata = '{"jane@example.com": "key stays", "n": 12345678901234567890, "a": {"b": ["deep@example.com", 1]}}',
			source_extra = '{"contact": "u=jane%40example.com"}',
			type_details = '{"v": 1, "web": {"param": "jane@example.com"}}',
			related_locations = '[{"message": "see jane@example.com"}]', stacks = '[{"frames": [{"module": "m@example.com"}]}]',
			fingerprint = 'fp-jane@example.com-' || id::text, partial_fingerprints = '{"k": "jane@example.com"}',
			identity_key = '{"u": "jane@example.com"}', location_key = 'jane@example.com', correlation_id = 'c@example.com',
			cve_ids = ARRAY['CVE-2024-0001'], work_item_uris = ARRAY['https://t.example.com/?a=jane@example.com'],
			resolution = 'told jane@example.com'
			WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	mine := addressed(tenant, asset, "dast")
	human := addressed(tenant, asset, "pentest")
	foreign := addressed(other, otherAsset, "dast")
	versionsOnly := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset}).String()
	if _, err := db.ExecContext(ctx, `UPDATE findings SET title = 'lib@1.2.3 and image@sha256:abc' WHERE id = $1`, versionsOnly); err != nil {
		t.Fatal(err)
	}
	// Three plain findings, so the candidate pages (batch 2) span more than one page.
	for range 3 {
		f := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset}).String()
		if _, err := db.ExecContext(ctx, `UPDATE findings SET description = 'ping x' || $2 || '@example.com' WHERE id = $1`, f, f[:8]); err != nil {
			t.Fatal(err)
		}
	}

	body := "<p>Mail jane.doe@example.com</p><b>matched</b>"
	ms, me := strings.Index(body, "<b>"), strings.Index(body, "</b>")
	item := evidence.Item{
		Kind: evidence.KindHTTPExchange, Extracted: []string{"ops@example.org"},
		HTTP: &evidence.HTTP{
			Request: &evidence.HTTPRequest{Method: "GET", URL: "https://h.example.com/r?u=jane%40example.com",
				Headers: []evidence.Header{{Name: "From", Value: "jane.doe@example.com"}},
				Body:    base64.StdEncoding.EncodeToString([]byte("to=bob@example.net")), BodyEncoding: "base64"},
			Response: &evidence.HTTPResponse{Status: 200, Body: body},
		},
		Match: []evidence.Match{{Location: "response", Part: "body", Start: &ms, End: &me}},
	}
	binary := evidence.Item{Kind: evidence.KindHTTPExchange, HTTP: &evidence.HTTP{Response: &evidence.HTTPResponse{Status: 200,
		Body: base64.StdEncoding.EncodeToString([]byte{0, 'x', '@', 'e', 'x', '.', 'i', 'o', 0xff}), BodyEncoding: "base64"}}}
	addEvidence := func(tid shared.ID, fid string, content []byte) string {
		var id string
		if err := db.QueryRowContext(ctx, `INSERT INTO finding_evidence (tenant_id, finding_id, origin, kind, content, content_sha256, size_bytes)
			VALUES ($1, $2, 'detection', 'http_exchange', $3::jsonb, 'sha-before-masking', $4) RETURNING id`,
			tid.String(), fid, string(content), len(content)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	enc := func(it evidence.Item) []byte {
		b, err := json.Marshal(it)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	evMine := addEvidence(tenant, mine, enc(item))
	evBinary := addEvidence(tenant, mine, enc(binary))
	evUnknown := addEvidence(tenant, mine, []byte(`{"kind": "raw_text", "text": "x@example.com", "future_member": 1}`))
	evForeign := addEvidence(other, foreign, enc(item))

	snapshot := func(table, id string) string {
		var s string
		if err := db.QueryRowContext(ctx, `SELECT to_jsonb(r)::text FROM `+table+` r WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	type rowRef struct{ table, id string }
	refs := []rowRef{{"findings", mine}, {"findings", human}, {"findings", foreign}, {"findings", versionsOnly},
		{"finding_evidence", evMine}, {"finding_evidence", evBinary}, {"finding_evidence", evUnknown}, {"finding_evidence", evForeign}}
	snap := map[string]string{}
	for _, r := range refs {
		snap[r.id] = snapshot(r.table, r.id)
	}
	var evVersion, rowVersion int64
	if err := db.QueryRowContext(ctx, `SELECT evidence_version, row_version FROM findings WHERE id = $1`, mine).Scan(&evVersion, &rowVersion); err != nil {
		t.Fatal(err)
	}

	// Dry run: counts, nothing written.
	rep, err := ScrubStoredEmails(ctx, db, tenant, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Applied || rep.FindingsMasked != 4 || rep.HumanFindingsLeft != 1 || rep.EvidenceMasked != 1 || rep.EvidenceUnreadable != 1 || rep.Remaining != 0 {
		t.Fatalf("dry run = %+v", rep)
	}
	for _, c := range []string{"title", "message", "snippet", "context_snippet", "attack_prerequisites", "misconfig_expected",
		"scanner_output", "tags", "remediation", "metadata", "source_extra", "type_details", "related_locations", "stacks"} {
		if rep.Columns[c] != 1 {
			t.Errorf("dry run column %s = %d, want 1", c, rep.Columns[c])
		}
	}
	if rep.Columns["description"] != 4 {
		t.Errorf("dry run description = %d, want 4", rep.Columns["description"])
	}
	for _, r := range refs {
		if snapshot(r.table, r.id) != snap[r.id] {
			t.Fatalf("a dry run changed %s %s", r.table, r.id)
		}
	}

	// Apply.
	rep, err = ScrubStoredEmails(ctx, db, tenant, true, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Applied || rep.FindingsMasked != 4 || rep.HumanFindingsLeft != 1 || rep.EvidenceMasked != 1 || rep.EvidenceUnreadable != 1 || rep.Remaining != 0 {
		t.Fatalf("apply = %+v", rep)
	}
	var title, message, description, tags, metadata, sourceExtra, remediation, status string
	var newRowVersion, newEvVersion int64
	if err := db.QueryRowContext(ctx, `SELECT title, message, description, tags::text, metadata::text, source_extra::text,
		remediation::text, status, row_version, evidence_version FROM findings WHERE id = $1`, mine).Scan(
		&title, &message, &description, &tags, &metadata, &sourceExtra, &remediation, &status, &newRowVersion, &newEvVersion); err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		title: "Contact ***@Example.COM", message: "GET /?u=***%40example.com",
		description: "Staff: ***@example.org, lib@1.2.3, image@sha256:abc", tags: `{owner:***@example.org,lib@1.2.3,NULL}`,
		remediation: `{"steps": ["x"], "recommendation": "mail ***@example.com"}`, sourceExtra: `{"contact": "u=***%40example.com"}`,
		metadata: `{"a": {"b": ["***@example.com", 1]}, "n": 12345678901234567890, "jane@example.com": "key stays"}`,
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
	if status != "new" || newEvVersion != evVersion || newRowVersion != rowVersion+1 {
		t.Errorf("status %q, evidence_version %d->%d, row_version %d->%d", status, evVersion, newEvVersion, rowVersion, newRowVersion)
	}
	// Identifiers and person-written columns keep their values.
	var ids string
	if err := db.QueryRowContext(ctx, `SELECT concat_ws('|', fingerprint, partial_fingerprints::text, identity_key::text, location_key,
		correlation_id, rule_id, file_path, array_to_string(work_item_uris, ','), resolution) FROM findings WHERE id = $1`, mine).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if strings.Count(ids, "jane@example.com") != 7 || !strings.Contains(ids, "r@example.com") || !strings.Contains(ids, "c@example.com") {
		t.Errorf("an identifier changed: %s", ids)
	}
	for _, id := range []string{human, foreign, versionsOnly} {
		if snapshot("findings", id) != snap[id] {
			t.Errorf("finding %s changed", id)
		}
	}
	for _, id := range []string{evBinary, evUnknown, evForeign} {
		if snapshot("finding_evidence", id) != snap[id] {
			t.Errorf("evidence %s changed", id)
		}
	}

	var content, sha string
	var size int
	if err := db.QueryRowContext(ctx, `SELECT content::text, content_sha256, size_bytes FROM finding_evidence WHERE id = $1`, evMine).Scan(&content, &sha, &size); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"jane.doe@", "ops@", "bob@", "jane%40"} {
		if strings.Contains(content, addr) {
			t.Errorf("%q left in evidence %s", addr, content)
		}
	}
	var got evidence.Item
	if err := json.Unmarshal([]byte(content), &got); err != nil {
		t.Fatal(err)
	}
	if sha != "sha-before-masking" || size != len(enc(got)) {
		t.Errorf("sha %q size %d (want %d)", sha, size, len(enc(got)))
	}
	if q := got.HTTP.Request; q.Body != "to=***@example.net" || q.BodyEncoding != "" || q.Headers[0].Value != "***@example.com" {
		t.Errorf("request = %+v", q)
	}
	if m := got.Match[0]; got.HTTP.Response.Body[*m.Start:*m.End] != "<b>matched" {
		t.Errorf("match points at %q", got.HTTP.Response.Body[*m.Start:*m.End])
	}

	// Idempotent.
	rep, err = ScrubStoredEmails(ctx, db, tenant, true, 2)
	if err != nil || rep.FindingsMasked != 0 || rep.EvidenceMasked != 0 || len(rep.Columns) != 0 {
		t.Fatalf("second apply = %+v, %v", rep, err)
	}
	if rep.HumanFindingsLeft != 1 || rep.EvidenceUnreadable != 1 {
		t.Errorf("second apply should still report what it leaves: %+v", rep)
	}

	// The other tenant is scrubbed only when named.
	rep, err = ScrubStoredEmails(ctx, db, other, true, 500)
	if err != nil || rep.FindingsMasked != 1 || rep.EvidenceMasked != 1 {
		t.Fatalf("other tenant = %+v, %v", rep, err)
	}
	if _, err := ScrubStoredEmails(ctx, db, shared.ID{}, false, 2); err == nil {
		t.Error("a run without a tenant must be refused")
	}
	tenants, err := EmailScrubTenants(ctx, db)
	if err != nil || !containsID(tenants, tenant) || !containsID(tenants, other) || containsID(tenants, shared.ID{}) {
		t.Errorf("tenants = %v, %v", tenants, err)
	}
}

// A dry run works on a read-only connection (the command opens one for a
// dry run: it never opens a transaction, so every statement is read-only).
func TestScrubStoredEmails_DryRunReadOnly_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	f := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset}).String()
	if _, err := db.ExecContext(ctx, `UPDATE findings SET title = 'x@example.com' WHERE id = $1`, f); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(testdb.URL())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("default_transaction_read_only", "on")
	u.RawQuery = q.Encode()
	ro, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	rep, err := ScrubStoredEmails(ctx, ro, tenant, false, 10)
	if err != nil || rep.FindingsMasked != 1 {
		t.Fatalf("read-only dry run = %+v, %v", rep, err)
	}
	var title string
	if err := db.QueryRowContext(ctx, `SELECT title FROM findings WHERE id = $1`, f).Scan(&title); err != nil || title != "x@example.com" {
		t.Errorf("a dry run wrote: %q, %v", title, err)
	}
}
