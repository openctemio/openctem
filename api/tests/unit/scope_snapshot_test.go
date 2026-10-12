package unit

// Scope snapshot per run (RFC-065 §9): the entries that covered the run's
// targets, the programs they belong to with attestation and exclusions, and
// a count of uncovered targets; another tenant's scope never appears.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type snapPrograms struct {
	list []*bountyprogram.Program
	excl []bountyprogram.Exclusion
}

func (p snapPrograms) List(_ context.Context, tenantID shared.ID, _ *shared.ID) ([]*bountyprogram.Program, error) {
	var out []*bountyprogram.Program
	for _, x := range p.list {
		if x.TenantID.Equals(tenantID) {
			out = append(out, x)
		}
	}
	return out, nil
}

func (p snapPrograms) Exclusions(_ context.Context, tenantID shared.ID, programID *shared.ID) ([]bountyprogram.Exclusion, error) {
	var out []bountyprogram.Exclusion
	for _, x := range p.excl {
		if x.TenantID.Equals(tenantID) && (programID == nil || x.ProgramID.Equals(*programID)) {
			out = append(out, x)
		}
	}
	return out, nil
}

type memStore struct {
	bodies map[string][]byte
	links  map[shared.ID]string
}

func (m *memStore) Record(_ context.Context, _, runID shared.ID, sum string, body []byte, _ time.Time) error {
	m.bodies[sum] = body
	m.links[runID] = sum
	return nil
}

func TestScopeSnapshot(t *testing.T) {
	ctx := context.Background()
	svc, tr, _, _ := newTestScopeService()
	tenant, other := shared.NewID(), shared.NewID()
	pid := shared.NewID()
	now := time.Now().UTC()
	user := shared.NewID()

	add := func(tid shared.ID, pattern string, program *shared.ID) *scopedom.Target {
		e, err := scopedom.NewEntry(tid, scopedom.TargetTypeDomain, pattern, "", "u", scopedom.EntryOptions{MaxTier: scopedom.TierActive})
		if err != nil {
			t.Fatal(err)
		}
		if program != nil {
			if err := e.SetAuthorization(scopedom.AuthProgram, program); err != nil {
				t.Fatal(err)
			}
		}
		if err := tr.Create(ctx, e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	prog := add(tenant, "*.acme.example", &pid)
	own := add(tenant, "corp.example", nil)
	add(tenant, "unused.example", nil)
	add(other, "*.acme.example2", nil)

	progs := snapPrograms{
		list: []*bountyprogram.Program{{ID: pid, TenantID: tenant, Name: "Acme", ProgramURL: "https://acme.example/sec",
			TermsSHA256: "abc", AcceptedBy: &user, AcceptedAt: &now}},
		excl: []bountyprogram.Exclusion{{TenantID: tenant, ProgramID: pid, TargetType: scopedom.TargetTypeDomain, Pattern: "admin.acme.example"}},
	}
	svc.SetProgramExclusions(progs)
	svc.SetProgramLister(progs)

	snap, err := svc.Snapshot(ctx, tenant, []string{"www.acme.example", "api.acme.example", "corp.example", "admin.acme.example", "nothing.example"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Targets != 5 || snap.Uncovered != 2 || len(snap.Entries) != 2 {
		t.Fatalf("snapshot: %+v", snap)
	}
	ids := map[string]bool{}
	for _, e := range snap.Entries {
		ids[e.ID] = true
	}
	if !ids[prog.ID().String()] || !ids[own.ID().String()] {
		t.Fatalf("entries: %+v", snap.Entries)
	}
	if len(snap.Programs) != 1 || snap.Programs[0].TermsSHA256 != "abc" || len(snap.Programs[0].Exclusions) != 1 ||
		snap.Programs[0].AcceptedBy != user.String() {
		t.Fatalf("programs: %+v", snap.Programs)
	}

	store := &memStore{bodies: map[string][]byte{}, links: map[shared.ID]string{}}
	rec := scope.NewSnapshotRecorder(svc, store)
	run1, run2 := shared.NewID(), shared.NewID()
	h1, err := rec.RecordRunSnapshot(ctx, tenant, run1, []string{"www.acme.example", "corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := rec.RecordRunSnapshot(ctx, tenant, run2, []string{"corp.example", "www.acme.example"})
	if h1 != h2 || len(store.bodies) != 1 {
		t.Fatalf("the same scope must give one body: %s %s %d", h1, h2, len(store.bodies))
	}
	var body map[string]any
	if err := json.Unmarshal(store.bodies[h1], &body); err != nil {
		t.Fatal(err)
	}
	for _, e := range body["entries"].([]any) {
		if e.(map[string]any)["pattern"] == "*.acme.example2" {
			t.Fatal("another tenant's entry in the snapshot")
		}
	}
}
