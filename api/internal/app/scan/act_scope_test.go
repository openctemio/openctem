package scan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubActScope refuses the listed targets and assets and records its input.
type stubActScope struct {
	targets map[string]string
	assets  map[shared.ID]bool
	err     error
	got     []actscope.Input
}

func (s *stubActScope) Check(_ context.Context, in actscope.Input) (*actscope.Decision, error) {
	s.got = append(s.got, in)
	if s.err != nil {
		return nil, s.err
	}
	d := &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}
	for _, t := range in.Targets {
		if r, ok := s.targets[t]; ok {
			d.RefusedTargets[t] = r
		}
	}
	for _, id := range in.AssetIDs {
		if s.assets[id] {
			d.RefusedAssets[id] = true
		}
	}
	return d, nil
}

func TestRefuseOutOfActScope(t *testing.T) {
	tenant, owner := shared.NewID(), shared.NewID()
	stub := &stubActScope{targets: map[string]string{"other.example.com": actscope.ReasonOutOfDataScope}}
	svc := &Service{actScope: stub, logger: logger.NewNop()}

	err := svc.refuseOutOfActScope(context.Background(), tenant, &owner, []string{"mine.example.com", "other.example.com"})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "TARGET_OUT_OF_SCOPE" || !errors.Is(err, shared.ErrValidation) ||
		!strings.Contains(err.Error(), "other.example.com") || strings.Contains(err.Error(), "mine.example.com") {
		t.Fatalf("err = %v, want TARGET_OUT_OF_SCOPE naming only the refused target", err)
	}
	if got := stub.got[0]; !got.TenantID.Equals(tenant) || got.FallbackUser == nil || !got.FallbackUser.Equals(owner) {
		t.Fatalf("checker input = %+v", got)
	}
	if err := svc.refuseOutOfActScope(context.Background(), tenant, nil, []string{"mine.example.com"}); err != nil {
		t.Fatalf("in-scope target refused: %v", err)
	}
	// A failed check refuses (fail closed).
	svc.actScope = &stubActScope{err: errors.New("db down")}
	if err := svc.refuseOutOfActScope(context.Background(), tenant, nil, []string{"mine.example.com"}); err == nil {
		t.Fatal("a failed act-scope check must refuse")
	}
}

// A run skips the direct targets and group members the actor may not scan;
// the scan owner acts when nobody triggers it in a request.
func TestResolveScanTargets_SkipsOutOfActScope(t *testing.T) {
	mine := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "mine.example.com"}
	theirs := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "theirs.example.com"}
	stub := &stubActScope{
		targets: map[string]string{"typed.example.org": actscope.ReasonNoScopeTarget},
		assets:  map[shared.ID]bool{theirs.ID: true},
	}
	svc := allowAllChecks(&Service{
		assetGroupRepo: &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{mine, theirs}},
		actScope:       stub,
		logger:         logger.NewNop(),
	})
	owner := shared.NewID()
	sc := testScan("nuclei", "typed.example.org", "ok.example.com")
	sc.AssetGroupID = shared.NewID()
	sc.CreatedBy = &owner

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Targets, []string{"ok.example.com", "mine.example.com"}) || got.OutOfScope != 2 {
		t.Fatalf("targets=%v outOfScope=%d", got.Targets, got.OutOfScope)
	}
	in := stub.got[0]
	if in.FallbackUser == nil || !in.FallbackUser.Equals(owner) || len(in.AssetIDs) != 2 || len(in.Targets) != 2 {
		t.Fatalf("checker input = %+v", in)
	}

	// Every target out of scope: nothing dispatched.
	stub.targets["ok.example.com"] = actscope.ReasonOutOfDataScope
	stub.assets[mine.ID] = true
	r, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Targets) != 0 {
		t.Fatalf("targets = %v, want none", r.Targets)
	}
	if err := recordResolvedTargets(sc, r, map[string]any{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a run with nothing in scope must be refused: %v", err)
	}

	svc.actScope = &stubActScope{err: errors.New("db down")}
	if _, err := svc.resolveScanTargets(context.Background(), sc); err == nil {
		t.Fatal("a failed act-scope check must stop the run")
	}
}

// The dispatch gate applies the act scope when asked, and fails closed when
// it is asked and not wired.
func TestResolveDispatchTargets_ActScope(t *testing.T) {
	tenant := shared.NewID()
	excl := &stubExclusions{}
	stub := &stubActScope{targets: map[string]string{"other.example.com": actscope.ReasonOutOfDataScope}}
	svc := &Service{scopeExclusions: excl, actScope: stub, attributionGate: &stubGate{}, logger: logger.NewNop()}
	in := DispatchTargetsInput{TenantID: tenant, Targets: []string{"mine.example.com", "other.example.com"}, ActScope: true}

	got, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Allowed, []string{"mine.example.com"}) || len(got.Refused) != 1 || got.Refused[0].Target != "other.example.com" {
		t.Fatalf("allowed=%v refused=%v", got.Allowed, got.Refused)
	}

	// Not asked: not checked (system paths).
	in.ActScope = false
	if got, err := svc.ResolveDispatchTargets(context.Background(), in); err != nil || len(got.Allowed) != 2 {
		t.Fatalf("without ActScope: %v, %v", got, err)
	}

	in.ActScope = true
	if _, err := (&Service{scopeExclusions: excl, attributionGate: &stubGate{}, logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), in); !errors.Is(err, ErrActScopeUnavailable) {
		t.Fatalf("asked and unwired: err = %v, want ErrActScopeUnavailable", err)
	}
	svc.actScope = &stubActScope{err: errors.New("db down")}
	if _, err := svc.ResolveDispatchTargets(context.Background(), in); err == nil {
		t.Fatal("a failed act-scope check must refuse the dispatch")
	}
}

// POST /commands: a member-created scan command naming a target outside the
// member's act scope is refused as a whole.
func TestGateCommandPayload_ActScope(t *testing.T) {
	stub := &stubActScope{targets: map[string]string{"other.example.com": actscope.ReasonOutOfDataScope}}
	svc := &Service{scopeExclusions: &stubExclusions{}, actScope: stub, logger: logger.NewNop()}
	payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{"mine.example.com", "other.example.com"}})
	if _, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil, payload); !errors.Is(err, ErrCommandTargetRefused) {
		t.Fatalf("err = %v, want ErrCommandTargetRefused", err)
	}
	ok, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{"mine.example.com"}})
	if _, err := svc.GateCommandPayload(context.Background(), shared.NewID(), nil, ok); err != nil {
		t.Fatalf("in-scope command refused: %v", err)
	}
}
