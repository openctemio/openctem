package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeRunUserRepo answers GetByIDs only; any other call panics on the nil
// embedded interface, which the test would surface.
type fakeRunUserRepo struct {
	user.Repository
	users   []*user.User
	gotIDs  []shared.ID
	callCnt int
}

func (f *fakeRunUserRepo) GetByIDs(_ context.Context, ids []shared.ID) ([]*user.User, error) {
	f.callCnt++
	f.gotIDs = append(f.gotIDs, ids...)
	return f.users, nil
}

func TestScanRunTriggerNames(t *testing.T) {
	named, err := user.New("ada@example.com", "Ada Lovelace")
	if err != nil {
		t.Fatal(err)
	}
	unnamed, err := user.New("grace@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRunUserRepo{users: []*user.User{named, unnamed}}
	h := NewScanHandler(nil, repo, nil, nil, logger.NewNop())

	runs := []*scanrun.Run{
		{ID: shared.NewID(), TriggeredBy: named.ID().String()},
		{ID: shared.NewID(), TriggeredBy: named.ID().String()}, // same user twice
		{ID: shared.NewID(), TriggeredBy: unnamed.ID().String()},
		{ID: shared.NewID(), TriggeredBy: "system"}, // not a user id
		{ID: shared.NewID(), TriggeredBy: ""},
	}
	names := h.resolveRunTriggerNames(context.Background(), runs...)

	if repo.callCnt != 1 {
		t.Fatalf("want one batched lookup, got %d", repo.callCnt)
	}
	if len(repo.gotIDs) != 2 {
		t.Fatalf("want the 2 distinct user ids looked up, got %v", repo.gotIDs)
	}

	cases := []struct {
		run  *scanrun.Run
		want string
	}{
		{runs[0], "Ada Lovelace"},
		{runs[2], "grace@example.com"}, // no display name: fall back to the email
		{runs[3], ""},                  // "system" keeps no name; the UI shows the trigger type
	}
	for _, c := range cases {
		got := withTriggerName(toRunResponse(c.run), names)
		if got.TriggeredByName != c.want {
			t.Errorf("triggered_by %q: name %q, want %q", c.run.TriggeredBy, got.TriggeredByName, c.want)
		}
		if got.TriggeredBy != c.run.TriggeredBy {
			t.Errorf("triggered_by must be kept as is, got %q", got.TriggeredBy)
		}
	}
}

func TestScanRunTriggerNames_NoUserRepoOrNoIDs(t *testing.T) {
	if got := NewScanHandler(nil, nil, nil, nil, logger.NewNop()).
		resolveRunTriggerNames(context.Background(), &scanrun.Run{TriggeredBy: shared.NewID().String()}); got != nil {
		t.Fatalf("no user repo: want nil map, got %v", got)
	}
	repo := &fakeRunUserRepo{}
	h := NewScanHandler(nil, repo, nil, nil, logger.NewNop())
	if got := h.resolveRunTriggerNames(context.Background(), &scanrun.Run{TriggeredBy: "webhook:github"}); got != nil {
		t.Fatalf("no user ids: want nil map, got %v", got)
	}
	if repo.callCnt != 0 {
		t.Fatal("no user ids: the repository must not be queried")
	}
}
