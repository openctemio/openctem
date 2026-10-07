package integration

// The active-scan ownership gate on a migrated database with the production
// wiring (easm.ActiveGate over the real repositories), through every scan
// entry point: scan create, clone, import, quick scan, POST /commands, a
// scan run (manual, scheduled and retry share TriggerScan) and the dispatch
// gate (scan workflows, coverage, validation, retests, simulations, connector
// scans). Design: docs/rfcs/RFC-036-easm.md §6.3; architecture:
// docs/architecture/active-probe-gate.md.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func ownershipGate(db *sql.DB) *easmapp.ActiveGate {
	pg := &postgres.DB{DB: db}
	return easmapp.NewActiveGate(postgres.NewAttributionRepository(pg), postgres.NewAssetRepository(pg),
		scopeService(db), postgres.NewEASMSeedRepository(pg))
}

func seedOwnedAsset(t *testing.T, db *sql.DB, tenant shared.ID, name, typ string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
		id.String(), tenant.String(), name, typ); err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	return id
}

func decide(t *testing.T, db *sql.DB, tenant, asset shared.ID, state attribution.State) {
	t.Helper()
	ok, err := postgres.NewAttributionRepository(&postgres.DB{DB: db}).SaveDecision(context.Background(), tenant, asset.String(), state, "")
	if err != nil || !ok {
		t.Fatalf("decide %s: %v %v", state, ok, err)
	}
}

func automatic(t *testing.T, db *sql.DB, tenant, asset shared.ID, state attribution.State) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 85)`,
		asset.String(), tenant.String(), string(state)); err != nil {
		t.Fatalf("record %s: %v", state, err)
	}
}

func TestScanOwnershipGate(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	// Tenant A authorizes *.scoped.example.com and seeds example.org.
	seedScopeTarget(t, db, tenantA, "domain", "*.scoped.example.com")
	if _, err := db.ExecContext(ctx, `INSERT INTO easm_seeds (id, tenant_id, kind, value) VALUES ($1, $2, 'root_domain', 'example.org')`,
		shared.NewID().String(), tenantA.String()); err != nil {
		t.Fatal(err)
	}

	// Allowed: unrecorded inside a scope target, unrecorded under a seed,
	// confirmed by a person inside a scope target.
	seedOwnedAsset(t, db, tenantA, "app.scoped.example.com", "subdomain")
	seedOwnedAsset(t, db, tenantA, "www.example.org", "subdomain")
	confirmedIn := seedOwnedAsset(t, db, tenantA, "mine.scoped.example.com", "subdomain")
	decide(t, db, tenantA, confirmedIn, attribution.StateConfirmed)
	// Refused: confirmed by a person on the Ownership tab but outside every
	// scope target, seed and verified domain (RFC-054 §4.2: ownership is not
	// authority).
	confirmed := seedOwnedAsset(t, db, tenantA, "confirmed.example.net", "domain")
	decide(t, db, tenantA, confirmed, attribution.StateConfirmed)

	// Refused: rejected (B1), needs review (22b MED 3), candidate,
	// unattributed (22b HIGH 1), and a name under a rejected one.
	rejected := seedOwnedAsset(t, db, tenantA, "www.scoped.example.com", "subdomain")
	decide(t, db, tenantA, rejected, attribution.StateRejected)
	review := seedOwnedAsset(t, db, tenantA, "dev.scoped.example.com", "subdomain")
	automatic(t, db, tenantA, review, attribution.StateNeedsReview)
	candidate := seedOwnedAsset(t, db, tenantA, "cand.example.org", "subdomain")
	automatic(t, db, tenantA, candidate, attribution.StateCandidate)
	seedOwnedAsset(t, db, tenantA, "manual.example.net", "domain")

	// Tenant B rejects a name tenant A scans, and authorizes what A does
	// not: neither changes anything for A.
	bName := seedOwnedAsset(t, db, tenantB, "app.scoped.example.com", "subdomain")
	decide(t, db, tenantB, bName, attribution.StateRejected)
	seedScopeTarget(t, db, tenantB, "domain", "*.example.net")

	allowed := []string{"app.scoped.example.com", "www.example.org", "mine.scoped.example.com"}
	refusedTargets := []string{
		"www.scoped.example.com",               // rejected asset (B1)
		"https://www.scoped.example.com/login", // the same, as a URL
		"api.www.scoped.example.com",           // a name under the rejected one
		"dev.scoped.example.com",               // needs review
		"cand.example.org",                     // candidate
		"manual.example.net",                   // no record, outside scope and seeds
		"confirmed.example.net",                // confirmed, outside scope and seeds
		"free.example.net",                     // free text outside scope (tenant B's *.example.net does not count)
	}

	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(ownershipGate(db)))

	refused := func(t *testing.T, err error, target string) {
		t.Helper()
		var de *shared.DomainError
		if !errors.As(err, &de) || de.Code != "TARGET_OUT_OF_SCOPE" {
			t.Fatalf("%s: err = %v, want TARGET_OUT_OF_SCOPE", target, err)
		}
		// Each refused target is listed with its structured code (RFC-054 §6.5).
		details, _ := de.Details.(map[string]any)
		list, _ := details["refused"].([]scopedom.Refusal)
		if len(list) == 0 {
			t.Fatalf("%s: no structured refusal in %+v", target, de.Details)
		}
		for _, r := range list {
			if r.Code == "" || r.Message == "" || !strings.Contains(err.Error(), r.Message) {
				t.Fatalf("%s: refusal %+v not coded or not in the message %v", target, r, err)
			}
		}
	}
	create := func(targets ...string) (*shared.ID, error) {
		sc, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "own " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: targets, TenantRunner: true,
		})
		if err != nil {
			return nil, err
		}
		return &sc.ID, nil
	}

	t.Run("scan create", func(t *testing.T) {
		for _, target := range allowed {
			if _, err := create(target); err != nil {
				t.Fatalf("%s refused: %v", target, err)
			}
		}
		for _, target := range refusedTargets {
			_, err := create(target)
			refused(t, err, target)
		}
		want := map[string]string{
			"www.scoped.example.com": scopedom.RefusalRejected, "dev.scoped.example.com": scopedom.RefusalNeedsReview,
			"cand.example.org": scopedom.RefusalCandidate, "manual.example.net": scopedom.RefusalNoEntry,
			"confirmed.example.net": scopedom.RefusalNoEntry,
		}
		for target, code := range want {
			_, err := create(target)
			var de *shared.DomainError
			_ = errors.As(err, &de)
			list := de.Details.(map[string]any)["refused"].([]scopedom.Refusal)
			if list[0].Code != code {
				t.Errorf("%s: code %s, want %s", target, list[0].Code, code)
			}
		}
	})

	t.Run("quick scan", func(t *testing.T) {
		for _, target := range refusedTargets {
			_, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenantA.String(), ScannerName: "httpx", Targets: []string{target}})
			refused(t, err, target)
		}
		// The allowed side of the same check is the scan-create case above.
	})

	t.Run("import", func(t *testing.T) {
		data := []byte(`{"name":"imported ` + shared.NewID().String() + `","scan_type":"single","scanner_name":"nuclei","targets":["www.scoped.example.com"]}`)
		_, err := svc.ImportConfig(ctx, tenantA, data, shared.NewID().String())
		refused(t, err, "import")
	})

	t.Run("POST /commands", func(t *testing.T) {
		for _, target := range refusedTargets {
			_, err := svc.GateCommandPayload(ctx, tenantA, nil, []byte(`{"scanner":"nuclei","targets":["`+target+`"]}`))
			if !errors.Is(err, scansvc.ErrCommandTargetRefused) {
				t.Fatalf("%s: err = %v", target, err)
			}
		}
	})

	t.Run("run, retry and clone after the asset is rejected", func(t *testing.T) {
		later := seedOwnedAsset(t, db, tenantA, "later.scoped.example.com", "subdomain")
		id, err := create("later.scoped.example.com", "app.scoped.example.com")
		if err != nil {
			t.Fatal(err)
		}
		decide(t, db, tenantA, later, attribution.StateRejected)

		if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantA.String(), ScanID: id.String()}); err != nil {
			t.Fatalf("trigger: %v", err)
		}
		if got := lastCommandTargets(t, db, tenantA); !slices.Equal(got, []string{"app.scoped.example.com"}) {
			t.Fatalf("command targets = %v, the rejected name must be skipped", got)
		}
		_, err = svc.CloneScan(ctx, tenantA.String(), id.String(), "clone "+shared.NewID().String(), shared.NewID().String())
		refused(t, err, "clone")

		only, err := create("other.scoped.example.com")
		if err != nil {
			t.Fatal(err)
		}
		o := seedOwnedAsset(t, db, tenantA, "other.scoped.example.com", "subdomain")
		decide(t, db, tenantA, o, attribution.StateRejected)
		var de *shared.DomainError
		if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantA.String(), ScanID: only.String()}); !errors.As(err, &de) || de.Code != "ALL_TARGETS_UNCONFIRMED" {
			t.Fatalf("a run of only refused targets: err = %v", err)
		}
		// The retry controller goes through the same trigger: no command.
		before := countRows(t, db, `SELECT count(*) FROM commands WHERE tenant_id = $1`, tenantA)
		_ = svc.RetryScanRun(ctx, tenantA, *only, 1)
		if after := countRows(t, db, `SELECT count(*) FROM commands WHERE tenant_id = $1`, tenantA); after != before {
			t.Fatalf("a retry of only refused targets dispatched %d command(s)", after-before)
		}
	})

	t.Run("dispatch gate", func(t *testing.T) {
		got, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{
			TenantID: tenantA, Targets: append(slices.Clone(allowed), refusedTargets...),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Allowed, allowed) {
			t.Fatalf("allowed = %v, want %v", got.Allowed, allowed)
		}
		if len(got.Refused) != len(refusedTargets) {
			t.Fatalf("refused = %+v", got.Refused)
		}
		// By asset id (coverage, validation): the same decisions.
		got, err = svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{
			TenantID: tenantA, Targets: []string{"10.20.30.40"},
			Assets: map[string]scansvc.DispatchAsset{"10.20.30.40": {IDs: []string{review.String()}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Allowed) != 0 {
			t.Fatalf("needs-review asset by id allowed: %v", got.Allowed)
		}
	})

	t.Run("cross-tenant", func(t *testing.T) {
		// Tenant B's rejection of app.scoped.example.com does not refuse
		// tenant A (checked above: allowed). Tenant B's scope target does not
		// authorize tenant A's manual.example.net (checked above: refused).
		// Tenant A's rejection does not refuse tenant B's free text as
		// rejected (B has no scope there, so it is unattributed, never
		// rejected), tenant B's own scope target covers its free text, and
		// tenant A's asset ids resolve to nothing in tenant B.
		gate := ownershipGate(db)
		b, err := gate.BlockedTargets(ctx, tenantB, []string{"www.scoped.example.com", "api.www.scoped.example.com", "x.example.net"})
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"www.scoped.example.com", "api.www.scoped.example.com"} {
			if b[n] != attribution.StateUnattributed {
				t.Fatalf("tenant B %s = %q, want unattributed (never tenant A's rejection)", n, b[n])
			}
		}
		if st, no := b["x.example.net"]; no {
			t.Fatalf("tenant B's own scope target did not cover its free text: %s", st)
		}
		ids, err := gate.ActiveCheckBlocked(ctx, tenantB, []string{confirmed.String()})
		if err != nil || ids[confirmed.String()] != attribution.StateUnattributed {
			t.Fatalf("tenant A's asset id in tenant B: %v %v", ids, err)
		}
	})
}

func lastCommandTargets(t *testing.T, db *sql.DB, tenant shared.ID) []string {
	t.Helper()
	var raw []byte
	if err := db.QueryRowContext(context.Background(),
		`SELECT payload FROM commands WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`, tenant.String()).Scan(&raw); err != nil {
		t.Fatalf("read command: %v", err)
	}
	var p struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.Targets
}
