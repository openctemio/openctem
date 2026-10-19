package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// adoptingRepo holds the given keys as live findings and records each
// re-key attempt.
type adoptingRepo struct {
	stubFindingRepository
	live    map[string]bool
	adopted []string
}

func (r *adoptingRepo) CheckFingerprintsExist(_ context.Context, _ shared.ID, fps []string) (map[string]bool, error) {
	m := make(map[string]bool, len(fps))
	for _, fp := range fps {
		m[fp] = r.live[fp]
	}
	return m, nil
}

func (r *adoptingRepo) AdoptFingerprint(_ context.Context, _ shared.ID, from, _ string, _ []byte, _ int, _ vulnerability.AdoptGuard) (bool, error) {
	r.adopted = append(r.adopted, from)
	return true, nil
}

type adoptItem struct {
	v1 string
	k  vulnerability.IdentityKey
}

// A batch of new findings (no live version-1 key) issues no re-key UPDATE at
// all; only a version-1 key a live finding holds is re-keyed.
func TestAdoptV1Keys_OnlyLiveKeysAreRekeyed(t *testing.T) {
	repo := &adoptingRepo{live: map[string]bool{"v1-live": true}}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	items := []adoptItem{
		{v1: "v1-live", k: vulnerability.NewIdentityKey("test", "host", "a.example.test")},
		{v1: "v1-new-1", k: vulnerability.NewIdentityKey("test", "host", "b.example.test")},
		{v1: "v1-new-2", k: vulnerability.NewIdentityKey("test", "host", "c.example.test")},
	}
	adoptV1KeysOf(context.Background(), p, shared.NewID(), items, func(it adoptItem) adoptKeys {
		k := it.k
		return adoptKeys{from: it.v1, identity: &k}
	})
	if len(repo.adopted) != 1 || repo.adopted[0] != "v1-live" {
		t.Fatalf("adopted = %v, want only v1-live", repo.adopted)
	}

	repo.adopted, repo.live = nil, map[string]bool{}
	adoptV1KeysOf(context.Background(), p, shared.NewID(), items, func(it adoptItem) adoptKeys {
		k := it.k
		return adoptKeys{from: it.v1, identity: &k}
	})
	if len(repo.adopted) != 0 {
		t.Fatalf("new findings issued %d re-key updates, want 0", len(repo.adopted))
	}
}
