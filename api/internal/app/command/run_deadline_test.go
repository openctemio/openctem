package command

import (
	"context"
	"errors"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type deadlineRepo struct {
	commanddom.Repository
	calls  int
	tenant shared.ID
	sensor shared.ID
	ids    []shared.ID
	err    error
}

func (r *deadlineRepo) ExtendRunDeadlinesAtClaim(_ context.Context, tenantID, sensorID shared.ID, ids []shared.ID) error {
	r.calls++
	r.tenant, r.sensor, r.ids = tenantID, sensorID, ids
	return r.err
}

// The claim hands the claimed ids, with the claiming sensor and its tenant,
// to the deadline extender; a failure keeps the claim; nothing claimed or a
// repository without the extension is a no-op.
func TestExtendRunDeadlines(t *testing.T) {
	tid, sid, id := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &deadlineRepo{}
	s := &Service{repo: repo, logger: logger.NewNop()}

	s.extendRunDeadlines(context.Background(), tid, sid, []shared.ID{id})
	if repo.calls != 1 || repo.tenant != tid || repo.sensor != sid || len(repo.ids) != 1 || repo.ids[0] != id {
		t.Fatalf("extender got %+v", repo)
	}
	s.extendRunDeadlines(context.Background(), tid, sid, nil)
	if repo.calls != 1 {
		t.Fatal("an empty claim must not call the extender")
	}
	repo.err = errors.New("db down")
	s.extendRunDeadlines(context.Background(), tid, sid, []shared.ID{id}) // must not panic or fail
	if repo.calls != 2 {
		t.Fatalf("calls = %d", repo.calls)
	}

	plain := &Service{repo: replayRepo{}, logger: logger.NewNop()}
	plain.extendRunDeadlines(context.Background(), tid, sid, []shared.ID{id})
}
