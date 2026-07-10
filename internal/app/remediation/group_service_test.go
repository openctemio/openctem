package remediation

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app/finding"
	remediationdom "github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type mockKeyRepo struct {
	groups   []remediationdom.Group
	openIDs  []shared.ID
	openErr  error
	lastKey  string
	lastExcl []string
}

func (m *mockKeyRepo) Upsert(_ context.Context, _, _ shared.ID, _, _ string) error { return nil }
func (m *mockKeyRepo) Delete(_ context.Context, _ shared.ID) error                 { return nil }
func (m *mockKeyRepo) ListGroups(_ context.Context, _ shared.ID, excl []string) ([]remediationdom.Group, error) {
	m.lastExcl = excl
	return m.groups, nil
}
func (m *mockKeyRepo) OpenFindingIDs(_ context.Context, _ shared.ID, key string, excl []string) ([]shared.ID, error) {
	m.lastKey = key
	m.lastExcl = excl
	return m.openIDs, m.openErr
}

func (m *mockKeyRepo) CountByKey(_ context.Context, _ shared.ID, _ string, _ []string) (int64, int64, error) {
	return 0, 0, nil
}

type mockResolver struct {
	gotInput finding.BulkUpdateStatusInput
	called   bool
}

func (m *mockResolver) BulkUpdateFindingsStatus(_ context.Context, _ string, in finding.BulkUpdateStatusInput) (*finding.BulkUpdateResult, error) {
	m.called = true
	m.gotInput = in
	return &finding.BulkUpdateResult{Updated: len(in.FindingIDs)}, nil
}

type mockGuard struct {
	err      error
	gotSize  int
	approved bool
}

func (m *mockGuard) CheckBulk(_ context.Context, _ shared.ID, size int, approved bool) error {
	m.gotSize = size
	m.approved = approved
	return m.err
}

func newSvc(keys *mockKeyRepo, res *mockResolver, guard *mockGuard) *GroupService {
	var g Guard
	if guard != nil {
		g = guard
	}
	return NewGroupService(keys, res, g, logger.NewNop())
}

// Resolve defaults to fix_applied and passes the group's open IDs to the bulk path.
func TestResolveGroup_DefaultsToFixApplied(t *testing.T) {
	ids := []shared.ID{shared.NewID(), shared.NewID()}
	keys := &mockKeyRepo{openIDs: ids}
	res := &mockResolver{}
	guard := &mockGuard{}
	svc := newSvc(keys, res, guard)

	out, err := svc.ResolveGroup(context.Background(), shared.NewID(), ResolveGroupInput{Key: "sol:abc", OperatorApproved: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.called {
		t.Fatal("expected the bulk resolver to be called")
	}
	if res.gotInput.Status != "fix_applied" {
		t.Errorf("expected default status fix_applied, got %q", res.gotInput.Status)
	}
	if len(res.gotInput.FindingIDs) != 2 {
		t.Errorf("expected 2 finding IDs, got %d", len(res.gotInput.FindingIDs))
	}
	if guard.gotSize != 2 || !guard.approved {
		t.Errorf("guard not invoked with (size=2, approved=true): size=%d approved=%v", guard.gotSize, guard.approved)
	}
	if out.Updated != 2 {
		t.Errorf("expected Updated=2, got %d", out.Updated)
	}
	if keys.lastKey != "sol:abc" {
		t.Errorf("expected OpenFindingIDs called with key, got %q", keys.lastKey)
	}
}

// An invalid target status is rejected before any resolve.
func TestResolveGroup_InvalidStatusRejected(t *testing.T) {
	res := &mockResolver{}
	svc := newSvc(&mockKeyRepo{}, res, nil)

	_, err := svc.ResolveGroup(context.Background(), shared.NewID(), ResolveGroupInput{Key: "k", Status: "new"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
	if res.called {
		t.Error("resolver must not be called on invalid status")
	}
}

// An empty group is a no-op (no resolver call).
func TestResolveGroup_EmptyGroupNoop(t *testing.T) {
	res := &mockResolver{}
	svc := newSvc(&mockKeyRepo{openIDs: nil}, res, &mockGuard{})

	out, err := svc.ResolveGroup(context.Background(), shared.NewID(), ResolveGroupInput{Key: "k"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.called {
		t.Error("resolver must not be called for an empty group")
	}
	if out.Updated != 0 {
		t.Errorf("expected Updated=0, got %d", out.Updated)
	}
}

// The abuse guard blocks an over-ceiling resolve before any status change.
func TestResolveGroup_GuardBlocks(t *testing.T) {
	res := &mockResolver{}
	guard := &mockGuard{err: errors.New("too large")}
	svc := newSvc(&mockKeyRepo{openIDs: []shared.ID{shared.NewID()}}, res, guard)

	if _, err := svc.ResolveGroup(context.Background(), shared.NewID(), ResolveGroupInput{Key: "k"}); err == nil {
		t.Fatal("expected guard error")
	}
	if res.called {
		t.Error("resolver must not be called when the guard blocks")
	}
}

// sanitizeLogValue strips CR/LF/control chars so a user-controlled key can't
// forge log entries (CodeQL log-injection).
func TestSanitizeLogValue(t *testing.T) {
	if got := sanitizeLogValue("sol:abc\ninjected: fake"); got != "sol:abcinjected: fake" {
		t.Errorf("newline not stripped: %q", got)
	}
	if got := sanitizeLogValue("a\r\nb\tc"); got != "abc" {
		t.Errorf("control chars not stripped: %q", got)
	}
	if got := sanitizeLogValue("sca:pkg:npm/lodash"); got != "sca:pkg:npm/lodash" {
		t.Errorf("legit key altered: %q", got)
	}
}

// ListGroups excludes closed statuses (passes them to the repo).
func TestListGroups_ExcludesClosed(t *testing.T) {
	keys := &mockKeyRepo{groups: []remediationdom.Group{{Key: "sol:x", FindingCount: 3}}}
	svc := newSvc(keys, &mockResolver{}, nil)

	got, err := svc.ListGroups(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Key != "sol:x" {
		t.Errorf("unexpected groups: %+v", got)
	}
	if len(keys.lastExcl) == 0 {
		t.Error("expected closed statuses to be passed as the exclusion list")
	}
}
