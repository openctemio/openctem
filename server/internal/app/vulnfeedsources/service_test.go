package vulnfeedsources

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/internal/app/vulnfeed"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const (
	official = "SHA256:official"
	custom   = "SHA256:custom"
)

func newSvc(env Env) (*Service, *cst.Repo, *cst.Audit, *cst.Notifier) {
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	if env.OfficialRootKeyID == "" {
		env.OfficialRootKeyID = official
	}
	if env.RootKeyID == "" {
		env.RootKeyID = official
	}
	return NewService(repo, cst.Recorder(audit, n), env, logger.NewNop()), repo, audit, n
}

type fakeProber struct {
	base    string
	mirrors []string
	calls   int
}

func (p *fakeProber) Probe(_ context.Context, base string, mirrors []string) []vulnfeed.ProbeResult {
	p.base, p.mirrors, p.calls = base, mirrors, p.calls+1
	return []vulnfeed.ProbeResult{{Origin: base, OK: true}}
}

// Nothing stored: the server's values; a console value wins at once and is
// what the importer and the relay read.
func TestDefaultsAndConsoleChange(t *testing.T) {
	ctx := context.Background()
	svc, _, audit, notifier := newSvc(Env{BaseURL: "", Mirrors: nil})
	s, err := svc.Get(ctx)
	if err != nil || s.Source != SourceDefault || s.BaseURL != vulnfeed.DefaultBaseURL || len(s.Mirrors) != 0 || s.LockedByEnvironment {
		t.Fatalf("default: %+v %v", s, err)
	}
	if !s.RootOfficial || s.RootKeyID != official || s.BundleDirSet {
		t.Fatalf("root/bundle: %+v", s)
	}
	in := Input{BaseURL: " https://feed.example.org/releases/ ", Mirrors: []string{"https://m1.example.org/v", ""},
		Reason: "move to the company mirror", Version: 0}
	s, err = svc.Update(ctx, cst.SuperAdmin(t), in, "192.0.2.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != SourceConsole || s.BaseURL != "https://feed.example.org/releases" || !slices.Equal(s.Mirrors, []string{"https://m1.example.org/v"}) || s.Version != 1 {
		t.Fatalf("after change: %+v", s)
	}
	base, mirrors := svc.FeedSources(ctx)
	if base != "https://feed.example.org/releases" || len(mirrors) != 1 {
		t.Fatalf("feed sources %s %v", base, mirrors)
	}
	if got := svc.RelayOrigin(); got != "https://feed.example.org/releases/latest/download" {
		t.Fatalf("relay origin %s", got)
	}
	// One critical audit row with old and new values and the reason;
	// every administrator told.
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged {
		t.Fatalf("audit entries %d", len(audit.Entries))
	}
	js := audit.JSON(t)
	for _, want := range []string{`"critical"`, `"previous_release":"` + vulnfeed.DefaultBaseURL + `"`, `"release":"https://feed.example.org/releases"`,
		`"previous_source":"default"`, "move to the company mirror", `"mirrors":["https://m1.example.org/v"]`} {
		if !strings.Contains(js, want) {
			t.Fatalf("audit lacks %s: %s", want, js)
		}
	}
	if notifier.Count() != 1 {
		t.Fatalf("administrators told %d times", notifier.Count())
	}
	// A stale form is refused.
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{BaseURL: "https://x.example.org/r", Reason: "r", Version: 0}, "", ""); err == nil {
		t.Fatal("a stale version was accepted")
	}
}

// The environment pins the value: shown locked, never changed here.
func TestLockedByEnvironment(t *testing.T) {
	ctx := context.Background()
	svc, repo, audit, _ := newSvc(Env{BaseURL: "https://env.example.org/releases", Mirrors: []string{"https://m.example.org/x"},
		Pinned: true, RootKeyID: custom, BundleDirSet: true})
	s, err := svc.Get(ctx)
	if err != nil || !s.LockedByEnvironment || s.Source != SourceEnvironment || s.BaseURL != "https://env.example.org/releases" {
		t.Fatalf("pinned: %+v %v", s, err)
	}
	if s.RootOfficial || s.RootKeyID != custom || !s.BundleDirSet {
		t.Fatalf("custom root / bundle dir: %+v", s)
	}
	_, err = svc.Update(ctx, cst.SuperAdmin(t), Input{BaseURL: "https://feed.example.org/r", Reason: "r"}, "", "")
	if !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("locked: %v", err)
	}
	if repo.Raw(SettingKey) != "" || len(audit.Entries) != 0 {
		t.Fatal("a locked setting was stored or audited")
	}
	// A value stored before the variable was set is ignored.
	if _, err := repo.CreateIfAbsent(ctx, SettingKey, platformsetting.State{Value: []byte(`{"base_url":"https://old.example.org/r"}`), Version: 1}); err != nil {
		t.Fatal(err)
	}
	base, _ := svc.FeedSources(ctx)
	if base != "https://env.example.org/releases" {
		t.Fatalf("pinned feed sources: %s", base)
	}
}

// Every unsafe address is refused before anything is stored.
func TestUpdateRefusals(t *testing.T) {
	ctx := context.Background()
	svc, repo, audit, _ := newSvc(Env{})
	if _, err := svc.Update(ctx, nil, Input{BaseURL: "https://feed.example.org/r", Reason: "r"}, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{BaseURL: "https://feed.example.org/r"}, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	six := []string{}
	for _, h := range []string{"a", "b", "c", "d", "e", "f"} {
		six = append(six, "https://"+h+".example.org/x")
	}
	for name, in := range map[string]Input{
		"http":           {BaseURL: "http://feed.example.org/r"},
		"credentials":    {BaseURL: "https://user:secret@feed.example.org/r"},
		"query":          {BaseURL: "https://feed.example.org/r?token=x"},
		"fragment":       {BaseURL: "https://feed.example.org/r#x"},
		"loopback":       {BaseURL: "https://127.0.0.1/r"},
		"private":        {BaseURL: "https://10.1.2.3/r"},
		"metadata":       {BaseURL: "https://169.254.169.254/latest"},
		"empty":          {BaseURL: ""},
		"http mirror":    {BaseURL: "https://feed.example.org/r", Mirrors: []string{"http://m.example.org/x"}},
		"private mirror": {BaseURL: "https://feed.example.org/r", Mirrors: []string{"https://192.168.1.1/x"}},
		"cred mirror":    {BaseURL: "https://feed.example.org/r", Mirrors: []string{"https://a:b@m.example.org/x"}},
		"dup mirror":     {BaseURL: "https://feed.example.org/r", Mirrors: []string{"https://m.example.org/x", "https://M.example.org/x/"}},
		"mirror is base": {BaseURL: "https://feed.example.org/r", Mirrors: []string{"https://feed.example.org/r/"}},
		"too many":       {BaseURL: "https://feed.example.org/r", Mirrors: six},
	} {
		in.Reason = "r"
		if _, err := svc.Update(ctx, cst.SuperAdmin(t), in, "", ""); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if repo.Raw(SettingKey) != "" || len(audit.Entries) != 0 {
		t.Fatal("a refused change was stored or audited")
	}
}

// A stored value that no longer validates (written by hand or by an older
// build) is never used: the server's configuration applies.
func TestInvalidStoredValueFallsBack(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, _ := newSvc(Env{BaseURL: "https://env.example.org/releases"})
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{BaseURL: "https://feed.example.org/r", Reason: "r"}, "", ""); err != nil {
		t.Fatal(err)
	}
	st, _ := repo.Get(ctx, SettingKey)
	st.Value = []byte(`{"base_url":"https://127.0.0.1/r","mirrors":[]}`)
	repo.Rows[SettingKey] = st
	svc.store.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	base, _ := svc.FeedSources(ctx)
	if base != "https://env.example.org/releases" {
		t.Fatalf("an invalid stored value was used: %s", base)
	}
}

// The test fetch never runs where the platform makes no outbound request,
// and tests the values in force when none are given.
func TestTestFetch(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(Env{BaseURL: "https://env.example.org/releases", Mirrors: []string{"https://m.example.org/x"}})
	if _, err := svc.Test(ctx, nil, "", nil, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Test(ctx, cst.SuperAdmin(t), "", nil, "", ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("no prober: %v", err)
	}
	p := &fakeProber{}
	svc.SetProber(p)
	res, err := svc.Test(ctx, cst.SuperAdmin(t), "", nil, "192.0.2.1", "ua")
	if err != nil || len(res) != 1 || p.base != "https://env.example.org/releases" || !slices.Equal(p.mirrors, []string{"https://m.example.org/x"}) {
		t.Fatalf("in force: %+v %v %+v", res, err, p)
	}
	if _, err := svc.Test(ctx, cst.SuperAdmin(t), "https://feed.example.org/r", []string{"https://n.example.org/y/"}, "192.0.2.1", "ua"); err != nil || p.base != "https://feed.example.org/r" || p.mirrors[0] != "https://n.example.org/y" {
		t.Fatalf("given: %v %+v", err, p)
	}
	calls := p.calls
	if _, err := svc.Test(ctx, cst.SuperAdmin(t), "https://10.0.0.1/r", nil, "192.0.2.1", "ua"); !errors.Is(err, shared.ErrValidation) || p.calls != calls {
		t.Fatalf("internal address tested: %v", err)
	}
	svc.SetRelayMode(func(context.Context) bool { return true })
	if _, err := svc.Test(ctx, cst.SuperAdmin(t), "", nil, "192.0.2.1", "ua"); !errors.Is(err, ErrRelayMode) || p.calls != calls {
		t.Fatalf("relay mode: %v", err)
	}
	dirSvc, _, _, _ := newSvc(Env{BundleDirSet: true})
	dirSvc.SetProber(p)
	if _, err := dirSvc.Test(ctx, cst.SuperAdmin(t), "", nil, "192.0.2.1", "ua"); !errors.Is(err, ErrBundleDir) || p.calls != calls {
		t.Fatalf("bundle dir: %v", err)
	}
}

// Every test fetch is audited (not a change: high, no notice) with the
// addresses and the public outcome, and a refused one with its reason; the
// precise cause never reaches the audit or the answer.
func TestTestFetchAudited(t *testing.T) {
	ctx := context.Background()
	svc, _, audit, notifier := newSvc(Env{BaseURL: "https://env.example.org/releases"})
	svc.SetProber(failingProber{})
	res, err := svc.Test(ctx, cst.SuperAdmin(t), "https://probe.example.org/r", nil, "192.0.2.7", "ua")
	if err != nil || len(res) != 1 || res[0].Error != vulnfeed.ProbeNotVerified {
		t.Fatalf("test: %+v %v", res, err)
	}
	if _, err := svc.Test(ctx, cst.SuperAdmin(t), "https://10.0.0.1/r", nil, "192.0.2.7", "ua"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("internal: %v", err)
	}
	if len(audit.Entries) != 2 || audit.Entries[0].Action != ActionTested || audit.Entries[1].Action != ActionTested {
		t.Fatalf("audit entries %+v", audit.Entries)
	}
	js := audit.JSON(t)
	for _, want := range []string{`"release":"https://probe.example.org/r"`, `"error":"not_verified"`, `"refused":"invalid_address"`, `192.0.2.7`} {
		if !strings.Contains(js, want) {
			t.Errorf("audit lacks %s: %s", want, js)
		}
	}
	for _, leak := range []string{"http_error", "502"} {
		if strings.Contains(js, leak) {
			t.Errorf("audit leaks %s", leak)
		}
	}
	if len(notifier.Subjects) != 0 {
		t.Fatalf("a test fetch notified administrators")
	}
}

type failingProber struct{}

func (failingProber) Probe(_ context.Context, base string, _ []string) []vulnfeed.ProbeResult {
	return []vulnfeed.ProbeResult{{Origin: base, Error: vulnfeed.ProbeNotVerified, Cause: vulnfeed.ProbeHTTPError, HTTPStatus: 502}}
}
