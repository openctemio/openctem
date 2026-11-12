package integration

// Template facts (docs/architecture/template-facts.md) through the real
// ingest on a migrated database: a template scanner's info matches add
// technologies as secondary readings (a probe's source is kept), a version
// a template extracted joins the technology, an unknown plugin joins the
// asset, and nothing reaches another tenant.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// nucleiLine is one nuclei v3 JSONL result on the origin, with the raw
// exchange the extracted values travel in.
func nucleiLine(id, matcher string, extracted []string, meta string) string {
	ex := ""
	if len(extracted) > 0 {
		b, _ := json.Marshal(extracted)
		ex = `,"extracted-results":` + string(b)
	}
	m := `{"max-request":1` + meta + `}`
	return `{"template-id":"` + id + `","info":{"name":"` + id + `","tags":["tech"],"severity":"info","metadata":` + m + `},` +
		`"matcher-name":"` + matcher + `","type":"http","port":"443","scheme":"https","host":"https://www.facts.example.com",` +
		`"matched-at":"https://www.facts.example.com/","timestamp":"2026-11-05T10:00:00Z","matcher-status":true,` +
		`"request":"GET / HTTP/1.1\r\nHost: www.facts.example.com\r\n\r\n",` +
		`"response":"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n<html>5.3.1</html>"` + ex + `}`
}

func TestTemplateFacts_TechnologiesThroughIngest(t *testing.T) {
	g := newTechRig(t)
	other := g.r.newTenant("httpx")
	const name = "www.facts.example.com"
	now := time.Now().UTC()
	g.send(g.tn, "httpx", now.Add(-30*time.Minute), "", ctis.Asset{ID: "o", Type: ctis.AssetTypeWebOrigin, Value: "https://" + name,
		Technologies: techsOf("nginx", "Cloudflare")})

	tid := g.tn.tenant
	agt := &sensor.Sensor{ID: g.tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmd := shared.NewID()
	jsonl := strings.Join([]string{
		nucleiLine("tech-detect", "nginx", nil, ""),
		nucleiLine("nginx-version", "", []string{"nginx/1.25.3"}, ""),
		nucleiLine("wordpress-akismet", "", []string{"5.3.1"}, `,"plugin_namespace":"akismet"`),
	}, "\n")
	parsed, err := importer.Parse(context.Background(), strings.NewReader(jsonl), importer.Options{Format: importer.FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	rep := parsed.Report
	rep.Metadata.GeneratedAt = now.Add(-10 * time.Minute)
	bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"https://" + name}, Tool: "nuclei"}
	out, err := g.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("ingest errors: %v", out.Errors)
	}

	if out.InfoObservations != 0 {
		t.Fatalf("no exposure projector is wired: matches stay findings, facts are still recorded (got %d)", out.InfoObservations)
	}
	got := g.originTechnologies(g.tn)
	if got["nginx"].Source != "httpx" || got["nginx"].Version != "1.25.3" {
		t.Fatalf("nginx = %+v: the probe's source kept, the extracted version joined", got["nginx"])
	}
	if got["cloudflare"].Source != "httpx" {
		t.Fatalf("cloudflare = %+v", got["cloudflare"])
	}
	ak, ok := got["akismet"]
	if !ok || ak.Source != "nuclei" || ak.Version != "5.3.1" || ak.Confidence <= 0 || ak.Confidence >= 80 {
		t.Fatalf("akismet = %+v (%v)", ak, ok)
	}

	// The other tenant has nothing.
	var n int
	if err := g.r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM asset_technologies WHERE tenant_id = $1`,
		other.tenant.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("other tenant technologies = %d (%v)", n, err)
	}
}

// originTechnologies are the technologies of the tenant's only web origin.
func (g *setRig) originTechnologies(tn v2Tenant) map[string]assettech.Technology {
	g.t.Helper()
	var s string
	if err := g.r.db.QueryRowContext(context.Background(),
		`SELECT id FROM assets WHERE tenant_id = $1 AND sub_type = 'http'`, tn.tenant.String()).Scan(&s); err != nil {
		g.t.Fatalf("web origin: %v", err)
	}
	id, _ := shared.IDFromString(s)
	list, err := postgres.NewAssetTechnologyRepository(&postgres.DB{DB: g.r.db}).ListByAsset(context.Background(), tn.tenant, id)
	if err != nil {
		g.t.Fatal(err)
	}
	out := map[string]assettech.Technology{}
	for _, t := range list {
		out[t.Key] = t
	}
	return out
}
