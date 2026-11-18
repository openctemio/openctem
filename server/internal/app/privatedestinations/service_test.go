package privatedestinations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type applied struct{ lists [][]string }

func (a *applied) apply(l []string) error {
	a.lists = append(a.lists, append([]string{}, l...))
	return nil
}

func (a *applied) last() string {
	if len(a.lists) == 0 {
		return "<none>"
	}
	return strings.Join(a.lists[len(a.lists)-1], ",")
}

func newSvc() (*Service, *cst.Repo, *cst.Audit, *cst.Notifier, *applied) {
	repo, audit, n, ap := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}, &applied{}
	svc := NewService(repo, cst.Recorder(audit, n), logger.NewNop())
	svc.SetApplier(ap.apply)
	return svc, repo, audit, n, ap
}

// A change is canonicalized, stored, applied at once, audited critical with
// the old and new lists, and told to every administrator.
func TestUpdate_AppliesAndAudits(t *testing.T) {
	ctx := context.Background()
	svc, _, audit, n, ap := newSvc()
	v, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "192.168.77.9/24", Note: " GitLab "}, {CIDR: "10.0.0.0/8"}},
		"office GitLab", 0, "198.51.100.7", "test")
	if err != nil {
		t.Fatal(err)
	}
	if ap.last() != "192.168.77.0/24,10.0.0.0/8" {
		t.Fatalf("applied %s", ap.last())
	}
	if len(v.Console) != 2 || v.Console[0].CIDR != "192.168.77.0/24" || v.Console[0].Note != "GitLab" || v.Console[0].Wide || !v.Console[1].Wide {
		t.Fatalf("view %+v", v.Console)
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged || n.Count() != 1 {
		t.Fatalf("audit %d notices %d", len(audit.Entries), n.Count())
	}
	js := audit.JSON(t)
	if !strings.Contains(js, `"previous_ranges":[]`) || !strings.Contains(js, "192.168.77.0/24") || !strings.Contains(js, "office GitLab") {
		t.Fatalf("audit body %s", js)
	}

	if _, err := svc.Update(ctx, cst.SuperAdmin(t), nil, "close", v.Meta.Version, "", ""); err != nil {
		t.Fatal(err)
	}
	if ap.last() != "" {
		t.Fatalf("cleared list applied as %q", ap.last())
	}
	if !strings.Contains(audit.JSON(t), `"ranges":[]`) {
		t.Fatalf("cleared audit %s", audit.JSON(t))
	}
}

func TestUpdate_Refusals(t *testing.T) {
	ctx := context.Background()
	svc, _, audit, _, ap := newSvc()
	if _, err := svc.Update(ctx, nil, nil, "r", 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.1.0.0/16"}}, " ", 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	var re *httpsec.RangeError
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.1.0.0/16"}, {CIDR: "127.0.0.0/8"}}, "r", 0, "", ""); !errors.As(err, &re) || re.Index != 1 {
		t.Fatalf("loopback: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.1.0.0/16", Note: "a\nb"}}, "r", 0, "", ""); !errors.Is(err, httpsec.ErrRangeNoteNotPlain) {
		t.Fatalf("note: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.1.0.0/16"}}, "r", 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.2.0.0/16"}}, "r", 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if ap.last() != "10.1.0.0/16" || len(audit.Entries) != 1 {
		t.Fatalf("a refused change was applied or audited: %s %d", ap.last(), len(audit.Entries))
	}
}

// Another replica's change reaches this one on Refresh; a stored value that
// no longer passes the checks opens nothing; an unreadable store keeps the
// list in force.
func TestRefresh(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, _, ap := newSvc()
	other := NewService(repo, nil, logger.NewNop())
	other.SetApplier(func([]string) error { return nil })
	if _, err := other.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.5.0.0/16"}}, "r", 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(ctx); err != nil || ap.last() != "10.5.0.0/16" {
		t.Fatalf("refresh: %v %s", err, ap.last())
	}

	st, _ := repo.Get(ctx, SettingKey)
	bad, _ := json.Marshal(stored{Ranges: []Entry{{CIDR: "10.5.0.0/16"}, {CIDR: "127.0.0.0/8"}}})
	if _, err := repo.Update(ctx, SettingKey, bad, st.Version, shared.NewID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(ctx); err != nil || ap.last() != "" {
		t.Fatalf("an invalid stored list applied as %q (%v)", ap.last(), err)
	}

	broken := NewService(failingRepo{}, nil, logger.NewNop())
	bap := &applied{}
	broken.SetApplier(bap.apply)
	if err := broken.Refresh(ctx); err == nil || len(bap.lists) != 0 {
		t.Fatalf("an unreadable store changed the guard: %v %v", err, bap.lists)
	}
}

type failingRepo struct{ platformsetting.Repository }

func (failingRepo) Get(context.Context, string) (platformsetting.State, error) {
	return platformsetting.State{}, errors.New("database down")
}

// Where anyone may create an organization, no range is opened: a change is
// refused (clearing stays allowed) and a stored list is not applied.
func TestOpenSignup(t *testing.T) {
	ctx := context.Background()
	svc, repo, audit, _, ap := newSvc()
	svc.SetSignupOpen(true)
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.1.0.0/16"}}, "r", 0, "", ""); !errors.Is(err, ErrOpenSignup) {
		t.Fatalf("open sign-up: %v", err)
	}
	if len(audit.Entries) != 0 || len(ap.lists) != 0 {
		t.Fatal("a refused change was applied or audited")
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), nil, "clear", 0, "", ""); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	other := NewService(repo, nil, logger.NewNop())
	other.SetApplier(func([]string) error { return nil })
	st, _ := repo.Get(ctx, SettingKey)
	if _, err := other.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.1.0.0/16"}}, "r", st.Version, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(ctx); err != nil || ap.last() != "" {
		t.Fatalf("stored list applied under open sign-up: %q %v", ap.last(), err)
	}
	if v, _ := svc.Get(ctx); !v.SignupOpen {
		t.Fatal("view does not say sign-up is open")
	}
}

// getHookRepo runs onGet once, after the first read it serves.
type getHookRepo struct {
	*cst.Repo
	onGet func()
}

func (r *getHookRepo) Get(ctx context.Context, key string) (platformsetting.State, error) {
	st, err := r.Repo.Get(ctx, key)
	if f := r.onGet; f != nil {
		r.onGet = nil
		f()
	}
	return st, err
}

// A refresh that read the stored list before a save on this server must not
// apply its older copy over the save: a range the administrator just closed
// would stay open until the next refresh.
func TestRefresh_ReadBeforeSaveDoesNotReapplyOldList(t *testing.T) {
	ctx := context.Background()
	repo := &getHookRepo{Repo: cst.NewRepo()}
	ap := &applied{}
	svc := NewService(repo, cst.Recorder(&cst.Audit{}, &cst.Notifier{}), logger.NewNop())
	svc.SetApplier(ap.apply)
	v, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "10.20.0.0/16"}, {CIDR: "192.168.77.0/24"}}, "open", 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// The refresh reads {10.20/16, 192.168.77/24}; before it applies, an
	// administrator closes 10.20/16.
	repo.onGet = func() {
		if _, err := svc.Update(ctx, cst.SuperAdmin(t), []Entry{{CIDR: "192.168.77.0/24"}}, "incident", v.Meta.Version, "", ""); err != nil {
			t.Error(err)
		}
	}
	if err := svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ap.last(); got != "192.168.77.0/24" {
		t.Fatalf("after the racing refresh the guard holds %q, want the saved list", got)
	}
	// The next refresh applies the stored list as usual.
	if err := svc.Refresh(ctx); err != nil || ap.last() != "192.168.77.0/24" {
		t.Fatalf("next refresh: %v %q", err, ap.last())
	}
}
