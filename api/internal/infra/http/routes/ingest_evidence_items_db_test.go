package routes

// A third-party tool pushes CTIS 1.6 evidence_items of every kind (and one
// kind the platform does not know) through sensor protocol v2: every item is
// stored, masked by the platform's own detector (even where the tool marked
// nothing), and the unknown kind is kept as text, never refused
// (docs/architecture/finding-evidence.md).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const thirdPartyToken = "tp-bearer-0123456789abcdefghij"

func TestIngest_ThirdPartyEvidenceItemsOfEveryKind_DB(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM assets WHERE tenant_id = $1`} {
			_, _ = h.db.Exec(q, h.tenantID)
		}
	})
	// The sensor reports the third-party tool installed (the v2 tool gate).
	if _, err := h.db.Exec(`UPDATE sensors SET reported_tools = '[{"name":"tp-scanner","installed":true}]',
		reported_tool_names = ARRAY['tp-scanner'], reported_at = NOW() WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	h.ingest.SetEvidenceStore(evidenceapp.NewService(postgres.NewFindingEvidenceRepository(&postgres.DB{DB: h.db}),
		cipher, nil, nil, nil, logger.NewNop()))

	items := []any{
		map[string]any{"kind": "http_exchange", "label": "login probe", "http": map[string]any{
			"request": map[string]any{"method": "POST", "url": "https://tp.example.com/login",
				"headers": []any{map[string]any{"name": "Authorization", "value": "Bearer " + thirdPartyToken}},
				"body":    `{"user":"a","password":"hunter2-secret"}`},
			"response": map[string]any{"status": 200, "body": "welcome admin"},
		}, "match": []any{map[string]any{"location": "response", "part": "body", "start": 0, "end": 7}}},
		map[string]any{"kind": "raw_text", "protocol": "tls", "text": "CN=tp.example.com, expired 2020"},
		map[string]any{"kind": "command_output", "command": "tp-check --target tp.example.com", "exit_code": 1, "text": "VULNERABLE"},
		map[string]any{"kind": "file_excerpt", "file": map[string]any{"path": "conf/app.ini", "start_line": 3, "end_line": 4, "snippet": "debug=true"}},
		map[string]any{"kind": "screenshot", "artifact": map[string]any{"media_type": "image/png", "size": 1234,
			"sha256": "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"}},
		map[string]any{"kind": "curl", "text": "curl -H 'Authorization: Bearer " + thirdPartyToken + "' https://tp.example.com/login"},
		map[string]any{"kind": "grpc_call", "data": map[string]any{"service": "acme.Auth", "method": "Login"}},
	}
	seg, _ := json.Marshal(map[string]any{
		"version":  "1.6",
		"metadata": map[string]any{"timestamp": "2026-10-07T12:00:00Z"},
		"tool":     map[string]any{"name": "tp-scanner"},
		"assets":   []any{map[string]any{"id": "web", "type": "domain", "value": "tp.example.com"}},
		"findings": []any{map[string]any{
			"type": "vulnerability", "severity": "high", "rule_id": "tp-login-check", "asset_ref": "web",
			"title": "Login exposes admin", "evidence_items": items,
		}},
	})
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, seg)
	h.expect(resp, raw, 202, "")
	h.work(id)

	rows, err := h.db.Query(`SELECT e.kind, e.content::text, e.masked_count FROM finding_evidence e
		JOIN findings f ON f.id = e.finding_id AND f.tenant_id = e.tenant_id
		WHERE e.tenant_id = $1 AND f.rule_id = 'tp-login-check' ORDER BY e.kind`, h.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	masked := 0
	for rows.Next() {
		var kind, content string
		var n int
		if err := rows.Scan(&kind, &content, &n); err != nil {
			t.Fatal(err)
		}
		got[kind] = content
		masked += n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"http_exchange", "raw_text", "command_output", "file_excerpt", "screenshot", "curl", "grpc_call"} {
		if _, ok := got[k]; !ok {
			t.Errorf("kind %s not stored (got %d kinds)", k, len(got))
		}
	}
	for k, c := range got {
		for _, secret := range []string{thirdPartyToken, "hunter2-secret"} {
			if strings.Contains(c, secret) {
				t.Errorf("%s stored the secret %q in clear", k, secret)
			}
		}
	}
	if !strings.Contains(got["grpc_call"], "acme.Auth") {
		t.Errorf("unknown kind not kept as text: %s", got["grpc_call"])
	}
	if masked < 2 {
		t.Errorf("masked values = %d, want the token and the password kept for reveal", masked)
	}
	var secrets int
	if err := h.db.QueryRow(`SELECT count(*) FROM finding_evidence_secrets WHERE tenant_id = $1`, h.tenantID).Scan(&secrets); err != nil {
		t.Fatal(err)
	}
	if secrets != masked {
		t.Errorf("secret rows = %d, masked = %d", secrets, masked)
	}
}
