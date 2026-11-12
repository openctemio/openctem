package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type stubPending struct {
	covered map[string]bool
	err     error
}

func (p stubPending) PendingCovered(_ context.Context, _ shared.ID, targets []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, t := range targets {
		if p.covered[t] {
			out[t] = true
		}
	}
	return out, p.err
}

// memWaits is a tenant-keyed in-memory ScopeWaitStore.
type memWaits struct {
	waits map[string]ScopeWait // tenant/scan
}

func waitKey(tenantID, scanID shared.ID) string { return tenantID.String() + "/" + scanID.String() }

func (m *memWaits) Create(_ context.Context, w ScopeWait) error {
	m.waits[waitKey(w.TenantID, w.ScanID)] = w
	return nil
}

func (m *memWaits) ListByTenant(_ context.Context, tenantID shared.ID, _ int) ([]ScopeWait, error) {
	var out []ScopeWait
	for _, w := range m.waits {
		if w.TenantID == tenantID {
			out = append(out, w)
		}
	}
	return out, nil
}

func (m *memWaits) Exists(_ context.Context, tenantID, scanID shared.ID) (bool, error) {
	_, ok := m.waits[waitKey(tenantID, scanID)]
	return ok, nil
}

func (m *memWaits) Claim(_ context.Context, tenantID, scanID shared.ID) (bool, error) {
	k := waitKey(tenantID, scanID)
	_, ok := m.waits[k]
	delete(m.waits, k)
	return ok, nil
}

// A scan may wait only when every refused target is covered by a pending
// entry; any other refusal (no entry, a rejected asset, the deny list) or a
// failed check refuses as before.
func TestAwaitingScopeTargets(t *testing.T) {
	tenant := shared.NewID()
	ctx := context.Background()
	svc := func(blocked map[string]attribution.State, pending stubPending) *Service {
		return &Service{
			attributionGate: &stubGate{blockedTyped: blocked},
			scopeWaits:      &memWaits{waits: map[string]ScopeWait{}},
			pendingScope:    pending,
			logger:          logger.NewNop(),
		}
	}
	pendingAll := stubPending{covered: map[string]bool{"*.acme.vn": true, "app.acme.vn": true}}

	cases := []struct {
		name    string
		blocked map[string]attribution.State
		pending stubPending
		want    bool
	}{
		{"all refused targets behind a pending entry", map[string]attribution.State{"*.acme.vn": attribution.StateUnattributed, "app.acme.vn": attribution.StateUnattributed}, pendingAll, true},
		{"nothing refused: no wait", map[string]attribution.State{}, pendingAll, false},
		{"one target has no entry at all", map[string]attribution.State{"*.acme.vn": attribution.StateUnattributed, "other.io": attribution.StateUnattributed}, pendingAll, false},
		{"a rejected asset is never waited on", map[string]attribution.State{"app.acme.vn": attribution.StateRejected}, pendingAll, false},
		{"the deny list is never waited on", map[string]attribution.State{"app.acme.vn": attribution.StatePlatformDenied}, pendingAll, false},
		{"a failed pending check refuses", map[string]attribution.State{"app.acme.vn": attribution.StateUnattributed}, stubPending{covered: pendingAll.covered, err: errors.New("db down")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := svc(c.blocked, c.pending).awaitingScopeTargets(ctx, tenant, []string{"*.acme.vn", "app.acme.vn", "other.io"}) != nil; got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}

	// Without the store wired, the option is off.
	s := svc(cases[0].blocked, pendingAll)
	s.scopeWaits = nil
	if s.awaitingScopeTargets(ctx, tenant, []string{"*.acme.vn"}) != nil {
		t.Fatal("no store: must not wait")
	}
	// A failed ownership check refuses.
	s = svc(nil, pendingAll)
	s.attributionGate = &stubGate{err: errors.New("db down")}
	if s.awaitingScopeTargets(ctx, tenant, []string{"*.acme.vn"}) != nil {
		t.Fatal("failed gate: must not wait")
	}
}

// When an entry comes into effect, a waiting scan whose targets now pass is
// claimed and started once, as the person who asked; one still refused keeps
// waiting; one run by hand since is dropped without a run. Waits of another
// tenant are never touched.
func TestStartScansAwaitingScope(t *testing.T) {
	ctx := context.Background()
	tenant, other := shared.NewID(), shared.NewID()
	requester := shared.NewID()
	repo := newMockScanRepository()
	mk := func(tid shared.ID, targets ...string) *scan.Scan {
		sc := testScan("nuclei", targets...)
		sc.ID, sc.TenantID = shared.NewID(), tid
		_ = repo.Create(ctx, sc)
		return sc
	}
	ready := mk(tenant, "app.acme.vn")
	still := mk(tenant, "app.acme.vn", "api.later.vn")
	ranByHand := mk(tenant, "app.acme.vn")
	now := time.Now()
	ranAt := now.Add(time.Minute)
	ranByHand.LastRunAt = &ranAt
	foreign := mk(other, "app.acme.vn")

	waits := &memWaits{waits: map[string]ScopeWait{}}
	for _, sc := range []*scan.Scan{ready, still, ranByHand, foreign} {
		_ = waits.Create(ctx, ScopeWait{ScanID: sc.ID, TenantID: sc.TenantID, RequestedBy: &requester, CreatedAt: now, ExpiresAt: now.Add(ScopeWaitTTL)})
	}
	var started []TriggerScanExecInput
	svc := &Service{
		scanRepo:        repo,
		attributionGate: &stubGate{blockedTyped: map[string]attribution.State{"api.later.vn": attribution.StateUnattributed}},
		scopeWaits:      waits,
		pendingScope:    stubPending{},
		logger:          logger.NewNop(),
		scopeWaitTrigger: func(_ context.Context, in TriggerScanExecInput) (*scanrun.Run, error) {
			started = append(started, in)
			return nil, nil
		},
	}

	svc.StartScansAwaitingScope(ctx, tenant)
	if len(started) != 1 || started[0].ScanID != ready.ID.String() || started[0].TenantID != tenant.String() ||
		started[0].TriggeredBy != requester.String() {
		t.Fatalf("started = %+v, want only the ready scan as the requester", started)
	}
	if ok, _ := waits.Exists(ctx, tenant, ready.ID); ok {
		t.Fatal("the started scan must be claimed")
	}
	if ok, _ := waits.Exists(ctx, tenant, still.ID); !ok {
		t.Fatal("a scan still refused must keep waiting")
	}
	if ok, _ := waits.Exists(ctx, tenant, ranByHand.ID); ok {
		t.Fatal("a scan run by hand since must stop waiting")
	}
	if ok, _ := waits.Exists(ctx, other, foreign.ID); !ok {
		t.Fatal("another tenant's wait was touched")
	}

	// A second pass starts nothing again (claimed once).
	svc.StartScansAwaitingScope(ctx, tenant)
	if len(started) != 1 {
		t.Fatalf("a scan started twice: %+v", started)
	}
}

// A scan waiting for its scope is not refused by the act scope for having
// no entry yet, only for the targets that wait; being outside the data
// scope (or not an asset for a restricted member) still refuses.
func TestRefuseOutOfActScopeAwaiting(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	act := &stubActScope{targets: map[string]string{
		"*.acme.vn":    actscope.ReasonNoScopeTarget,
		"other.io":     actscope.ReasonNoScopeTarget,
		"hidden.acme":  actscope.ReasonOutOfDataScope,
		"typed.member": actscope.ReasonNotAnAsset,
	}}
	svc := &Service{actScope: act, logger: logger.NewNop()}
	awaiting := map[string]bool{"*.acme.vn": true, "hidden.acme": true, "typed.member": true}

	if err := svc.refuseOutOfActScopeAwaiting(ctx, tenant, nil, []string{"*.acme.vn"}, awaiting); err != nil {
		t.Fatalf("a waiting target was refused: %v", err)
	}
	if err := svc.refuseOutOfActScopeAwaiting(ctx, tenant, nil, []string{"*.acme.vn"}, nil); err == nil {
		t.Fatal("without a wait, no entry must refuse")
	}
	for _, target := range []string{"other.io", "hidden.acme", "typed.member"} {
		if err := svc.refuseOutOfActScopeAwaiting(ctx, tenant, nil, []string{"*.acme.vn", target}, awaiting); err == nil {
			t.Fatalf("%s must still be refused", target)
		}
	}
}
