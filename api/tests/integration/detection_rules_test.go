package integration

// Detection rules (RFC-140) through the real ingest on a migrated database,
// with the built-in rule packs: a web service's Server header, title and
// cookie names become technologies with the pack as their source (and a
// versioned product a software component); a credential in its final URL
// becomes one masked exposure on the asset, never the value; nothing
// crosses tenants.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	contentruleapp "github.com/openctemio/openctem/api/internal/app/contentrule"
	"github.com/openctemio/openctem/api/internal/app/contentrule/builtin"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// builtinPlatform serves the built-in rule packs as stable platform packs.
type builtinPlatform struct {
	t     *testing.T
	packs map[string]*dom.PlatformPack
	data  map[string][]byte
}

func newBuiltinPlatform(t *testing.T) *builtinPlatform {
	t.Helper()
	b := &builtinPlatform{t: t, packs: map[string]*dom.PlatformPack{}, data: map[string][]byte{}}
	packs, err := builtin.Packs()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packs {
		raw, err := p.Archive()
		if err != nil {
			t.Fatal(err)
		}
		arc, err := dom.Canonicalize(strings.NewReader(string(raw)), dom.PlatformLimits)
		if err != nil {
			t.Fatal(err)
		}
		id := shared.NewID()
		pp := &dom.PlatformPack{}
		pp.ID, pp.Name, pp.Version, pp.Kind, pp.Digest = id, p.Name, p.Release, p.Kind, arc.Digest
		b.packs[id.String()], b.data[id.String()] = pp, arc.Canonical
	}
	return b
}

func (b *builtinPlatform) Channels(context.Context) ([]dom.ChannelPointer, error) {
	out := make([]dom.ChannelPointer, 0, len(b.packs))
	for _, p := range b.packs {
		out = append(out, dom.ChannelPointer{Name: p.Name, Channel: dom.ChannelStable, PackID: p.ID, Version: p.Version, Digest: p.Digest})
	}
	return out, nil
}

func (b *builtinPlatform) Archive(_ context.Context, id string) (*dom.PlatformPack, []byte, error) {
	p, ok := b.packs[id]
	if !ok {
		return nil, nil, dom.ErrNotFound
	}
	return p, b.data[id], nil
}

func newRulesRig(t *testing.T) *setRig {
	t.Helper()
	var assets *assetapp.AssetService
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		assets = wireSetReconciliation(svc, db)
		svc.SetTechnologyRepository(postgres.NewAssetTechnologyRepository(db))
		svc.SetSoftwareRepository(postgres.NewSoftwareRepository(db))
		rules := contentruleapp.NewService(newBuiltinPlatform(t), nil,
			postgres.NewEASMExposureWriter(db, postgres.NewEASMAlerter(db)),
			postgres.NewCommandContentPinsRepository(db),
			vulnerability.NewSecretFingerprinter([]byte("integration-test-server-secret")), nil)
		svc.SetDetectionRules(rules)
	})
	return &setRig{t: t, r: r, tn: r.newTenant("httpx"), assets: assets}
}

func TestDetectionRules_Ingest(t *testing.T) {
	g := newRulesRig(t)
	other := g.r.newTenant("httpx")
	ctx := context.Background()
	const host = "www.rules.example.com"
	const name = "https://" + host
	password := "Zq8" + "vN4pLm2"
	svc := func(at time.Time) ctis.Asset {
		return ctis.Asset{ID: "h", Type: ctis.AssetTypeHTTPService, Value: name, Name: host,
			Properties: ctis.Properties{
				"web_server":   "nginx/1.25.3",
				"title":        "Grafana",
				"redirect_url": "https://admin:" + password + "@" + host + "/login",
				"http_posture": map[string]any{"cookies": []any{map[string]any{"name": "PHPSESSID"}}},
			}}
	}
	now := time.Now().UTC()
	g.send(g.tn, "httpx", now.Add(-20*time.Minute), "", svc(now))

	got := g.technologies(g.tn, name)
	nginx := got["nginx"]
	if nginx.Version != "1.25.3" || nginx.Source != "rules:web-fingerprints-core@"+builtin.Release ||
		nginx.CPE != "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*" || nginx.Confidence != 90 {
		t.Fatalf("nginx = %+v (all %+v)", nginx, got)
	}
	for _, k := range []string{"grafana", "php"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s not detected: %+v", k, got)
		}
	}

	// One masked credential exposure on the asset; the value is nowhere in
	// the row.
	exposures := func(tenant shared.ID) []string {
		rows, err := g.r.db.QueryContext(ctx, `SELECT event_type || '|' || severity || '|' || details::text || '|' || title
			FROM exposure_events WHERE tenant_id = $1 AND source = $2`, tenant.String(), contentruleapp.ExposureSource)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	rows := exposures(g.tn.tenant)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "credential_leaked|high|") || !strings.Contains(rows[0], `"secret_masked": "Zq…m2"`) ||
		!strings.Contains(rows[0], `"rule_id": "credentials-in-url"`) || !strings.Contains(rows[0], `"pack_digest": "sha256:`) {
		t.Fatalf("exposures = %v", rows)
	}
	if strings.Contains(rows[0], password) || strings.Contains(rows[0], "vN4pLm2") {
		t.Fatalf("the exposure stores the secret: %s", rows[0])
	}
	var linked int
	if err := g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE tenant_id = $1 AND asset_id = $2 AND source = $3`,
		g.tn.tenant.String(), g.assetID(g.tn, name).String(), contentruleapp.ExposureSource).Scan(&linked); err != nil || linked != 1 {
		t.Fatalf("exposure not on the asset: %d %v", linked, err)
	}

	// The same report again: still one exposure (same keyed fingerprint).
	g.send(g.tn, "httpx", now.Add(-10*time.Minute), "", svc(now))
	if rows := exposures(g.tn.tenant); len(rows) != 1 {
		t.Fatalf("re-sighting duplicated the exposure: %v", rows)
	}

	// Another tenant's identical report raises its own exposure on its own
	// asset; tenant A's stay one and B reads none of A's.
	g.send(other, "httpx", now.Add(-5*time.Minute), "", svc(now))
	if rows := exposures(other.tenant); len(rows) != 1 {
		t.Fatalf("tenant B exposures = %v", rows)
	}
	if rows := exposures(g.tn.tenant); len(rows) != 1 {
		t.Fatalf("tenant A exposures after B = %v", rows)
	}
	var fpA, fpB string
	_ = g.r.db.QueryRowContext(ctx, `SELECT details->>'secret_fingerprint' FROM exposure_events WHERE tenant_id = $1 AND source = $2`,
		g.tn.tenant.String(), contentruleapp.ExposureSource).Scan(&fpA)
	_ = g.r.db.QueryRowContext(ctx, `SELECT details->>'secret_fingerprint' FROM exposure_events WHERE tenant_id = $1 AND source = $2`,
		other.tenant.String(), contentruleapp.ExposureSource).Scan(&fpB)
	if fpA == "" || fpA == fpB {
		t.Fatalf("fingerprints must be keyed per tenant: A=%q B=%q", fpA, fpB)
	}
}
