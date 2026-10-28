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

// ownershipGate is the gate of the hosted service (MANAGED_SERVICE): a job
// on platform sensors, or one whose sensor is not known yet, needs the
// ownership of what it probes confirmed; a job on the tenant's own sensors
// does not (placement.go). Self-hosted installs never confirm; the easm
// package tests cover that side.
func ownershipGate(db *sql.DB) *easmapp.ActiveGate {
	pg := &postgres.DB{DB: db}
	g := easmapp.NewActiveGate(postgres.NewAttributionRepository(pg), postgres.NewAssetRepository(pg),
		scopeService(db), postgres.NewVerifiedDomainNameRepository(pg))
	g.SetManagedService(true)
	return g
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
	// A former seed is the permanent entry *.example.org (research/53 SC1).
	seedScopeTarget(t, db, tenantA, "domain", "*.example.org")

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
	// Pending records outside every entry: no entry lifts them.
	review := seedOwnedAsset(t, db, tenantA, "dev.unscoped.example.com", "subdomain")
	automatic(t, db, tenantA, review, attribution.StateNeedsReview)
	candidate := seedOwnedAsset(t, db, tenantA, "cand.unscoped.example.com", "subdomain")
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
		"manual.example.net",                   // no record, outside scope and seeds
		"confirmed.example.net",                // confirmed, outside scope and seeds
		"free.example.net",                     // free text outside scope (tenant B's *.example.net does not count)
	}
	// Refused only for a job on platform sensors of the hosted service: a
	// pending record no entry covers, under one of the organization's
	// domains. A job on the organization's own sensors may reach them.
	confirmationOnly := []string{
		"dev.unscoped.example.com",  // needs review, no entry
		"cand.unscoped.example.com", // candidate, no entry
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
	// A scan whose jobs run on platform sensors: ownership confirmation applies.
	createOnPlatform := func(targets ...string) error {
		_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "own " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: targets, SensorPreference: "platform",
		})
		return err
	}

	t.Run("scan create", func(t *testing.T) {
		for _, target := range allowed {
			if _, err := create(target); err != nil {
				t.Fatalf("%s refused: %v", target, err)
			}
			if err := createOnPlatform(target); err != nil {
				t.Fatalf("%s refused on platform sensors: %v", target, err)
			}
		}
		for _, target := range refusedTargets {
			_, err := create(target)
			refused(t, err, target)
		}
		for _, target := range append(slices.Clone(refusedTargets), confirmationOnly...) {
			refused(t, createOnPlatform(target), target)
		}
		// On the organization's own sensors no confirmation is needed.
		for _, target := range confirmationOnly {
			if _, err := create(target); err != nil {
				t.Fatalf("%s refused on the organization's own sensor: %v", target, err)
			}
		}
		want := map[string]string{
			"www.scoped.example.com": scopedom.RefusalRejected, "dev.unscoped.example.com": scopedom.RefusalNeedsReview,
			"cand.unscoped.example.com": scopedom.RefusalCandidate, "manual.example.net": scopedom.RefusalNoEntry,
			"confirmed.example.net": scopedom.RefusalNoEntry,
		}
		for target, code := range want {
			err := createOnPlatform(target)
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
		// Without shared sensors a quick scan runs on the organization's own
		// sensors: no confirmation is needed.
		for _, target := range confirmationOnly {
			_, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenantA.String(), ScannerName: "httpx", Targets: []string{target}})
			var de *shared.DomainError
			if errors.As(err, &de) && de.Code == "TARGET_OUT_OF_SCOPE" {
				t.Fatalf("%s refused on the organization's own sensor: %v", target, err)
			}
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
		// A command goes to the organization's own sensor.
		for _, target := range confirmationOnly {
			_, err := svc.GateCommandPayload(ctx, tenantA, nil, []byte(`{"scanner":"nuclei","targets":["`+target+`"]}`))
			if errors.Is(err, scansvc.ErrCommandTargetRefused) {
				t.Fatalf("%s refused on the organization's own sensor", target)
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
			TenantID: tenantA, Targets: append(append(slices.Clone(allowed), refusedTargets...), confirmationOnly...),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Allowed, allowed) {
			t.Fatalf("allowed = %v, want %v", got.Allowed, allowed)
		}
		if len(got.Refused) != len(refusedTargets)+len(confirmationOnly) {
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

// TestScanOwnershipGate_PendingUnderEntry: an automatic pending record
// (needs_review, candidate) is no decision, so an active scope entry that
// covers the name lets scans reach it, a one-off entry included
// (research/117 F4). A person's decision, an exclusion, a rejection, an
// expired entry and another tenant's entry never do.
func TestScanOwnershipGate_PendingUnderEntry(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	seedScopeTarget(t, db, tenantA, "domain", "*.perm.example.com")
	seedScopeTarget(t, db, tenantA, "ip_range", "198.51.100.0/24")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// A one-off entry in effect, and one whose expiry passed (still marked
	// active: the expiry sweep has not run yet) and one the sweep marked.
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, expires_at)
	      VALUES ($1, 'domain', 'once.example.com', 'active', NOW() + interval '2 days')`, tenantA.String())
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, expires_at)
	      VALUES ($1, 'domain', 'lapsed.example.com', 'active', NOW() - interval '1 hour')`, tenantA.String())
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, expires_at)
	      VALUES ($1, 'domain', 'swept.example.com', 'expired', NOW() - interval '1 day')`, tenantA.String())
	seedApprovedExclusion(t, db, tenantA, "domain", "excl.perm.example.com")
	// Tenant B authorizes a name tenant A has pending.
	seedScopeTarget(t, db, tenantB, "domain", "*.theirs.example.com")

	pending := func(name, typ string, state attribution.State) shared.ID {
		id := seedOwnedAsset(t, db, tenantA, name, typ)
		automatic(t, db, tenantA, id, state)
		return id
	}
	pending("app.perm.example.com", "subdomain", attribution.StateNeedsReview)
	pending("cand.perm.example.com", "subdomain", attribution.StateCandidate)
	pending("198.51.100.20", "ip_address", attribution.StateNeedsReview)
	pending("once.example.com", "domain", attribution.StateNeedsReview)
	pending("lapsed.example.com", "domain", attribution.StateNeedsReview)
	pending("swept.example.com", "domain", attribution.StateNeedsReview)
	pending("excl.perm.example.com", "subdomain", attribution.StateNeedsReview)
	pending("app.theirs.example.com", "subdomain", attribution.StateNeedsReview)
	pending("203.0.113.20", "ip_address", attribution.StateNeedsReview)
	// A person's decisions under an entry.
	sentBack := seedOwnedAsset(t, db, tenantA, "back.perm.example.com", "subdomain")
	decide(t, db, tenantA, sentBack, attribution.StateNeedsReview)
	watched := seedOwnedAsset(t, db, tenantA, "watch.perm.example.com", "subdomain")
	decide(t, db, tenantA, watched, attribution.StateMonitorOnly)
	dep := seedOwnedAsset(t, db, tenantA, "198.51.100.21", "ip_address")
	decide(t, db, tenantA, dep, attribution.StateDependency)
	gone := seedOwnedAsset(t, db, tenantA, "gone.perm.example.com", "subdomain")
	decide(t, db, tenantA, gone, attribution.StateRejected)
	pending("api.gone.perm.example.com", "subdomain", attribution.StateNeedsReview)
	// A child never gets more than its host; another tenant's host decision
	// never applies.
	host := seedOwnedAsset(t, db, tenantA, "198.51.100.30", "ip_address")
	decide(t, db, tenantA, host, attribution.StateMonitorOnly)
	pending("198.51.100.30:443", "service", attribution.StateNeedsReview)
	pending("198.51.100.31:443", "service", attribution.StateNeedsReview)
	bHost := seedOwnedAsset(t, db, tenantB, "198.51.100.31", "ip_address")
	decide(t, db, tenantB, bHost, attribution.StateRejected)

	allowed := []string{"app.perm.example.com", "cand.perm.example.com", "198.51.100.20", "once.example.com", "https://once.example.com/x", "198.51.100.31:443"}
	refused := map[string]string{
		"lapsed.example.com":        scopedom.RefusalNeedsReview,
		"swept.example.com":         scopedom.RefusalNeedsReview,
		"app.theirs.example.com":    scopedom.RefusalNeedsReview,
		"203.0.113.20":              scopedom.RefusalNeedsReview,
		"back.perm.example.com":     scopedom.RefusalNeedsReview,
		"watch.perm.example.com":    "",
		"198.51.100.21":             "",
		"gone.perm.example.com":     scopedom.RefusalRejected,
		"api.gone.perm.example.com": scopedom.RefusalRejected,
		"198.51.100.30:443":         "",
	}
	// An exclusion is applied where targets are dispatched (a scan keeps its
	// other targets): checked in the dispatch gate below.
	const excluded = "excl.perm.example.com"

	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(ownershipGate(db)))

	for _, target := range allowed {
		if _, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "pend " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: []string{target}, SensorPreference: "platform",
		}); err != nil {
			t.Fatalf("%s refused: %v", target, err)
		}
	}
	for target, code := range refused {
		_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "pend " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: []string{target}, SensorPreference: "platform",
		})
		var de *shared.DomainError
		if !errors.As(err, &de) {
			t.Fatalf("%s: allowed, want refused (err %v)", target, err)
		}
		if code == "" {
			continue
		}
		details, _ := de.Details.(map[string]any)
		list, _ := details["refused"].([]scopedom.Refusal)
		if len(list) == 0 || list[0].Code != code {
			t.Errorf("%s: refusal %+v, want %s", target, list, code)
		}
	}

	t.Run("dispatch gate", func(t *testing.T) {
		targets := slices.Clone(allowed)
		for k := range refused {
			targets = append(targets, k)
		}
		targets = append(targets, excluded)
		got, err := svc.ResolveDispatchTargets(ctx, scansvc.DispatchTargetsInput{TenantID: tenantA, Targets: targets})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Allowed, allowed) {
			t.Fatalf("allowed = %v, want %v (an exclusion must win over the entry)", got.Allowed, allowed)
		}
	})

	t.Run("cross-tenant", func(t *testing.T) {
		// Tenant B's entry covers app.theirs.example.com for B only, and
		// tenant A's entries authorize nothing for B: B has no asset of
		// that name, so its free text is judged by B's scope.
		b, err := ownershipGate(db).BlockedTargets(ctx, tenantB, []string{"app.theirs.example.com", "app.perm.example.com", "once.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if _, no := b["app.theirs.example.com"]; no {
			t.Fatalf("tenant B's own entry refused: %v", b)
		}
		if b["app.perm.example.com"] != attribution.StateUnattributed || b["once.example.com"] != attribution.StateUnattributed {
			t.Fatalf("tenant A's entries reached tenant B: %v", b)
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
