package contentsource_test

// Rule sources against a real schema: sync to candidate snapshots, automatic
// and reviewed promotion (four-eyes), rollback, credentials (write-only,
// bound to the host), webhook, organization isolation (another tenant's
// source is not found for every operation), platform sources read-only,
// limits and features at their seams, and snapshot collection. Requires
// DATABASE_URL (CI applies every migration first).

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	app "github.com/openctemio/openctem/api/internal/app/contentsource"
	"github.com/openctemio/openctem/api/internal/infra/fetchers"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	cpdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func openDB(t *testing.T) *postgres.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping rule source DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		testdb.Skipf(t, "open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	return &postgres.DB{DB: db}
}

// memStore is a tenant-namespaced object store.
type memStore struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func (m *memStore) Upload(_ context.Context, tenantID, name, _ string, r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID + "/" + name
	m.objs[key] = b
	return key, nil
}

func (m *memStore) Download(_ context.Context, tenantID, key string) (io.ReadCloser, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !strings.HasPrefix(key, tenantID+"/") {
		return nil, "", errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(m.objs[key])), "application/x-tar", nil
}

func (m *memStore) Delete(_ context.Context, _, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}

// fakeLimits is the entitlement service with settable limits, denies and
// a failing lookup.
type fakeLimits struct {
	limits map[limits.Key]int
	used   map[limits.Key]int
	denied map[string]bool
	broken bool
}

func (f *fakeLimits) Check(_ context.Context, _ shared.ID, key limits.Key, delta int) error {
	if f.broken {
		return &limits.ErrLimitReached{Key: key, Unavailable: true}
	}
	lim, ok := f.limits[key]
	if !ok {
		return nil
	}
	if !limits.AllowAddition(lim, f.used[key], delta) {
		return &limits.ErrLimitReached{Key: key, Limit: lim, Used: f.used[key]}
	}
	return nil
}

func (f *fakeLimits) Limit(_ context.Context, _ shared.ID, key limits.Key) (int, error) {
	if f.broken {
		return 0, errors.New("limits unavailable")
	}
	if v, ok := f.limits[key]; ok {
		return v, nil
	}
	return limits.Unlimited, nil
}

func (f *fakeLimits) Allowed(_ context.Context, _ shared.ID, feature string) (bool, error) {
	if f.broken {
		return false, errors.New("limits unavailable")
	}
	return !f.denied[feature], nil
}

func (f *fakeLimits) Usable(ctx context.Context, tid shared.ID, feature string) (bool, error) {
	return f.Allowed(ctx, tid, feature)
}

// fakeGit serves a repository's content per ref, and records what a fetch
// was sent.
type fakeGit struct {
	mu      sync.Mutex
	commit  string
	files   map[string]string
	license string
	err     error
	last    fetchers.GitRequest
	calls   int
}

func (g *fakeGit) fetch(_ context.Context, req fetchers.GitRequest) (*fetchers.GitSnapshot, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.last, g.calls = req, g.calls+1
	if g.err != nil {
		return nil, g.err
	}
	out := &fetchers.GitSnapshot{Commit: g.commit, License: []byte(g.license)}
	for p, c := range g.files {
		out.Files = append(out.Files, fetchers.File{Path: p, Data: []byte(c)})
	}
	return out, nil
}

func (g *fakeGit) set(commit string, files map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.commit, g.files, g.err = commit, files, nil
}

func rule(id string) string {
	return "  - id: " + id + "\n    pattern: " + id + "()\n    message: m\n    languages: [go]\n    severity: ERROR\n"
}

func rulesFile(ids ...string) string {
	var b strings.Builder
	b.WriteString("rules:\n")
	for _, id := range ids {
		b.WriteString(rule(id))
	}
	return b.String()
}

type env struct {
	db      *postgres.DB
	repo    *postgres.ContentSourceRepository
	svc     *app.Service
	packs   *contentpackapp.Service
	enc     app.Encryptor
	git     *fakeGit
	lim     *fakeLimits
	private bool
	clock   time.Time
	tenantA shared.ID
	tenantB shared.ID
	user1   shared.ID
	user2   shared.ID
	user3   shared.ID
	userB   shared.ID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db := openDB(t)
	e := &env{db: db, repo: postgres.NewContentSourceRepository(db), git: &fakeGit{}, lim: &fakeLimits{
		limits: map[limits.Key]int{}, used: map[limits.Key]int{}, denied: map[string]bool{},
	}, clock: time.Now().UTC()}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, tid := range []*shared.ID{&e.tenantA, &e.tenantB} {
		*tid = shared.NewID()
		id := tid.String()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'rule sources', $2)`, id, "rs-"+id)
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id) })
	}
	for _, uid := range []*shared.ID{&e.user1, &e.user2, &e.user3, &e.userB} {
		*uid = shared.NewID()
		id := uid.String()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rs')`, id, "rs-"+id+"@example.com")
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	}
	signer, err := cpdom.NewSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	log := logger.NewNop()
	packs := contentpackapp.NewService(postgres.NewContentPackRepository(db), &memStore{objs: map[string][]byte{}}, signer, nil, log)
	enc, err := crypto.NewCipher(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e.packs, e.enc = packs, enc
	e.svc = e.service(e.repo, packs)
	return e
}

// service builds a rule source service over repo and packs, wired like the
// default one (tests wrap them to inject failures).
func (e *env) service(repo dom.Repository, packs app.PackStore) *app.Service {
	svc := app.NewService(repo, packs, e.lim, e.enc, nil, logger.NewNop())
	svc.SetFetcher(e.git.fetch, func(string) (bool, error) { return e.private, nil })
	svc.SetClock(func() time.Time { return e.clock })
	return svc
}

func (e *env) actor(tid shared.ID, uid shared.ID) app.Actor {
	return app.Actor{TenantID: tid, UserID: &uid}
}

func (e *env) create(t *testing.T, slug string, mut func(*app.CreateInput)) *dom.Source {
	t.Helper()
	in := app.CreateInput{Slug: slug, Name: slug, Kind: "semgrep-rules", URL: "https://git.example.com/acme/rules.git", Ref: "main", Path: "rules"}
	if mut != nil {
		mut(&in)
	}
	src, err := e.svc.Create(context.Background(), e.actor(e.tenantA, e.user1), in)
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	return src
}

// runSync makes src due and runs the worker once.
func (e *env) runSync(t *testing.T, src *dom.Source) *dom.Source {
	t.Helper()
	return e.runSyncOn(t, e.svc, src)
}

func (e *env) runSyncOn(t *testing.T, svc *app.Service, src *dom.Source) *dom.Source {
	t.Helper()
	ctx := context.Background()
	if err := e.repo.RequestSync(ctx, e.tenantA, src.ID, e.clock); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := e.repo.Get(ctx, e.tenantA, src.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (e *env) snapshots(t *testing.T, src *dom.Source) []*dom.Snapshot {
	t.Helper()
	list, _, err := e.svc.ListSnapshots(context.Background(), e.tenantA, src.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func sha(c byte) string { return strings.Repeat(string(c), 40) }

func TestRuleSources_SyncPromoteRollback_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-sast", nil)

	// First sync: a candidate with every check passed is promoted.
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1", "r2"), "README.md": "x"})
	src = e.runSync(t, src)
	if src.LastSyncStatus != dom.SyncSuccess || src.CurrentSnapshotID == nil || src.PreviousSnapshotID != nil {
		t.Fatalf("after first sync: status %s current %v previous %v (%s)", src.LastSyncStatus, src.CurrentSnapshotID, src.PreviousSnapshotID, src.LastSyncError)
	}
	if e.git.last.Path != "rules" || e.git.last.Ref != "main" || e.git.last.Token != "" {
		t.Fatalf("fetch request: %+v", e.git.last)
	}
	first, err := e.svc.GetSnapshot(ctx, e.tenantA, src.ID, *src.CurrentSnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != dom.StatePromoted || first.UpstreamRevision != sha('a') || first.RuleCount != 2 || len(first.FileIndex) != 2 ||
		first.Diff.AddedCount != 2 || !first.Checks.AutoPromote || first.ContentPackID == nil || len(first.Signature) == 0 {
		t.Fatalf("first snapshot: %+v", first)
	}

	// Same content again: nothing new.
	src = e.runSync(t, src)
	if n := len(e.snapshots(t, src)); n != 1 {
		t.Fatalf("an unchanged sync stored a snapshot: %d", n)
	}

	// New commit: added, removed and changed rules in the diff; promoted.
	e.git.set(sha('b'), map[string]string{"a.yaml": rulesFile("r2", "r3") + "    metadata: {x: 1}\n"})
	src = e.runSync(t, src)
	second, err := e.svc.GetSnapshot(ctx, e.tenantA, src.ID, *src.CurrentSnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if !src.PreviousSnapshotID.Equals(first.ID) || second.Diff.BaseSnapshotID != first.ID.String() ||
		strings.Join(second.Diff.Added, ",") != "r3" || strings.Join(second.Diff.Removed, ",") != "r1" {
		t.Fatalf("second snapshot diff: %+v", second.Diff)
	}

	// Rollback swaps current and previous.
	rolled, err := e.svc.Rollback(ctx, e.actor(e.tenantA, e.user1), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !rolled.CurrentSnapshotID.Equals(first.ID) || !rolled.PreviousSnapshotID.Equals(second.ID) {
		t.Fatalf("rollback: %+v", rolled)
	}

	// Only the current snapshot's pack is deliverable to sensors.
	deliver := e.deliverable(t)
	if len(deliver) != 1 || deliver[0] != first.ContentPackID.String() {
		t.Fatalf("deliverable packs after rollback: %v (want only the current snapshot's %s)", deliver, first.ContentPackID)
	}
}

func TestRuleSources_ReviewAndFourEyes_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-review", func(in *app.CreateInput) { in.Policy = "review" })

	e.git.set(sha('c'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	if src.CurrentSnapshotID != nil {
		t.Fatal("a review-policy candidate was promoted automatically")
	}
	list := e.snapshots(t, src)
	if len(list) != 1 || list[0].State != dom.StateCandidate || !list[0].ReviewRequired {
		t.Fatalf("candidate: %+v", list)
	}
	cand := list[0]
	// SECURITY: the member who last changed the source cannot promote it.
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user1), src.ID, cand.ID); !errors.Is(err, dom.ErrFourEyes) {
		t.Fatalf("self-promotion: %v", err)
	}
	// Another organization cannot see or promote it.
	if err := e.svc.Promote(ctx, e.actor(e.tenantB, e.userB), src.ID, cand.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant promotion: %v", err)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, cand.ID); err != nil {
		t.Fatalf("second member promotion: %v", err)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, cand.ID); !errors.Is(err, dom.ErrNotCandidate) {
		t.Fatalf("promoting twice: %v", err)
	}

	// A candidate raising the tier needs review even under auto: nuclei with
	// a state-changing request is T2.
	nsrc := e.create(t, "acme-nuclei", func(in *app.CreateInput) { in.Kind = "nuclei-templates" })
	e.git.set(sha('d'), map[string]string{"t.yaml": "id: t2-template\ninfo:\n  name: t\n  author: a\n  severity: info\nhttp:\n  - method: DELETE\n    path:\n      - \"{{BaseURL}}/x\"\n    matchers:\n      - type: status\n        status: [200]\n"})
	nsrc = e.runSync(t, nsrc)
	nl := e.snapshots(t, nsrc)
	if nsrc.CurrentSnapshotID != nil || len(nl) != 1 || !nl[0].ReviewRequired {
		t.Fatalf("tier-raising candidate: current %v snapshots %+v (%s)", nsrc.CurrentSnapshotID, nl, nsrc.LastSyncError)
	}
	if err := e.svc.Reject(ctx, e.actor(e.tenantA, e.user2), nsrc.ID, nl[0].ID, "not now"); err != nil {
		t.Fatal(err)
	}
}

func TestRuleSources_TenantIsolation_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-iso", nil)
	e.git.set(sha('e'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	b := e.actor(e.tenantB, e.userB)
	notFound := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s from another organization: %v, want not found", name, err)
		}
	}
	_, err := e.svc.Get(ctx, e.tenantB, src.ID)
	notFound("get", err)
	_, _, err = e.svc.ListSnapshots(ctx, e.tenantB, src.ID, 10, 0)
	notFound("list snapshots", err)
	_, err = e.svc.GetSnapshot(ctx, e.tenantB, src.ID, *src.CurrentSnapshotID)
	notFound("get snapshot", err)
	name := "x"
	_, err = e.svc.Update(ctx, b, src.ID, app.UpdateInput{Name: &name})
	notFound("update", err)
	_, err = e.svc.SetCredential(ctx, b, src.ID, "", "glpat-0123456789")
	notFound("set credential", err)
	_, err = e.svc.Rollback(ctx, b, src.ID)
	notFound("rollback", err)
	notFound("reject", e.svc.Reject(ctx, b, src.ID, *src.CurrentSnapshotID, ""))
	notFound("sync", e.svc.RequestSync(ctx, b, src.ID))
	_, err = e.svc.RotateWebhookSecret(ctx, b, src.ID)
	notFound("webhook", err)
	_, err = e.svc.Test(ctx, b, app.TestInput{SourceID: &src.ID})
	notFound("test", err)
	notFound("delete", e.svc.Delete(ctx, b, src.ID))
	if list, err := e.svc.List(ctx, e.tenantB, dom.ListFilter{}); err != nil || len(list) != 0 {
		t.Fatalf("another organization lists %d sources: %v", len(list), err)
	}
	// Tenant B may use the same slug: slugs are per organization.
	if _, err := e.svc.Create(ctx, b, app.CreateInput{Slug: "acme-iso", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/b.git", Ref: "main"}); err != nil {
		t.Fatalf("same slug in another organization: %v", err)
	}
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "acme-iso", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/b.git", Ref: "main"}); !errors.Is(err, shared.ErrAlreadyExists) {
		t.Fatalf("duplicate slug: %v", err)
	}
}

func TestRuleSources_PlatformSourcesReadOnly_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	offered, hidden := shared.NewID(), shared.NewID()
	for _, row := range []struct {
		id    shared.ID
		slug  string
		avail string
	}{{offered, "rs-official-" + offered.String()[:8], "default_on"}, {hidden, "rs-hidden-" + hidden.String()[:8], "hidden"}} {
		if _, err := e.db.ExecContext(ctx, `INSERT INTO content_sources (id, scope, slug, rule_namespace, name, kind, origin, url, ref, availability,
			official, credential_encrypted, credential_updated_at, last_sync_error)
			VALUES ($1, 'platform', $2, '', $2, 'semgrep-rules', 'git', 'https://git.internal.example/central/rules.git', 'main', $3, true,
			'sealed', now(), 'dial tcp 10.0.0.5:443: refused')`, row.id.String(), row.slug, row.avail); err != nil {
			t.Fatal(err)
		}
		id := row.id.String()
		t.Cleanup(func() { _, _ = e.db.ExecContext(context.Background(), `DELETE FROM content_sources WHERE id = $1`, id) })
	}
	a := e.actor(e.tenantA, e.user1)
	got, err := e.svc.Get(ctx, e.tenantA, offered)
	if err != nil || !got.IsPlatform() {
		t.Fatalf("offered platform source: %+v %v", got, err)
	}
	if _, err := e.svc.Get(ctx, e.tenantA, hidden); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("hidden platform source: %v", err)
	}
	name := "mine"
	if _, err := e.svc.Update(ctx, a, offered, app.UpdateInput{Name: &name}); !errors.Is(err, dom.ErrPlatformReadOnly) {
		t.Fatalf("update platform source: %v", err)
	}
	if err := e.svc.Delete(ctx, a, offered); !errors.Is(err, dom.ErrPlatformReadOnly) {
		t.Fatalf("delete platform source: %v", err)
	}
	if _, err := e.svc.Rollback(ctx, a, offered); !errors.Is(err, dom.ErrPlatformReadOnly) {
		t.Fatalf("roll back platform source: %v", err)
	}
	if _, err := e.svc.SetCredential(ctx, a, offered, "", "glpat-0123456789"); !errors.Is(err, dom.ErrPlatformReadOnly) {
		t.Fatalf("credential of a platform source: %v", err)
	}
	if _, err := e.svc.Update(ctx, a, hidden, app.UpdateInput{Name: &name}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("update hidden platform source: %v", err)
	}
	// The repository's tenant write never matches a platform row.
	got.Name = "hijacked"
	if err := e.repo.Update(ctx, got); !errors.Is(err, dom.ErrPlatformReadOnly) {
		t.Fatalf("repository update of a platform row: %v", err)
	}
	list, err := e.svc.List(ctx, e.tenantA, dom.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range list {
		if s.ID.Equals(hidden) {
			t.Fatal("hidden platform source listed")
		}
		found = found || s.ID.Equals(offered)
	}
	if !found {
		t.Fatal("offered platform source not listed")
	}
	// The worker never syncs a platform source on a tenant's behalf.
	if _, err := e.svc.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if e.git.calls != 0 {
		t.Fatalf("platform source fetched by the tenant worker: %d", e.git.calls)
	}
}

func TestRuleSources_Credential_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-cred", nil)
	a := e.actor(e.tenantA, e.user1)
	if _, err := e.svc.SetCredential(ctx, a, src.ID, "", "gldt-0123456789abcd"); !errors.Is(err, dom.ErrUsernameRequired) {
		t.Fatalf("deploy token without username: %v", err)
	}
	got, err := e.svc.SetCredential(ctx, a, src.ID, "gitlab+deploy-token-7", "gldt-0123456789abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialHint != "abcd" || got.AuthUsername != "gitlab+deploy-token-7" {
		t.Fatalf("credential state: %+v", got)
	}
	var raw string
	if err := e.db.QueryRowContext(ctx, `SELECT credential_encrypted FROM content_sources WHERE tenant_id = $1 AND id = $2`,
		e.tenantA.String(), src.ID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "gldt-0123456789abcd") {
		t.Fatal("the token is stored in clear")
	}
	e.git.set(sha('f'), map[string]string{"a.yaml": rulesFile("r1")})
	e.runSync(t, got)
	if e.git.last.Token != "gldt-0123456789abcd" || e.git.last.Username != "gitlab+deploy-token-7" {
		t.Fatalf("fetch credential: %q %q", e.git.last.Username, e.git.last.Token)
	}
	// SECURITY: a sealed credential copied to another source does not open.
	other := e.create(t, "acme-cred-2", nil)
	if _, err := e.db.ExecContext(ctx, `UPDATE content_sources SET credential_encrypted = $3, credential_updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, e.tenantA.String(), other.ID.String(), raw); err != nil {
		t.Fatal(err)
	}
	other = e.runSync(t, other)
	if other.LastSyncStatus != dom.SyncFailed || !strings.Contains(other.LastSyncError, "credential") {
		t.Fatalf("copied credential: %s %q", other.LastSyncStatus, other.LastSyncError)
	}
	// A new host clears the credential.
	url := "https://elsewhere.example.org/acme/rules.git"
	moved, err := e.svc.Update(ctx, a, src.ID, app.UpdateInput{URL: &url})
	if err != nil {
		t.Fatal(err)
	}
	if moved.HasCredential() || !moved.ConfigChangedBy.Equals(e.user1) {
		t.Fatalf("after host change: credential %v changed by %v", moved.HasCredential(), moved.ConfigChangedBy)
	}
}

func TestRuleSources_FailuresAndTest_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-bad", nil)
	e.git.set(sha('1'), map[string]string{"a.yaml": "rules:\n  - id: broken\n"})
	src = e.runSync(t, src)
	if src.LastSyncStatus != dom.SyncFailed || len(src.LastSyncReport) == 0 || src.CurrentSnapshotID != nil {
		t.Fatalf("lint failure: %s report %d", src.LastSyncStatus, len(src.LastSyncReport))
	}
	// A rule id longer than the key allows refuses the sync.
	e.git.set(sha('0'), map[string]string{"a.yaml": rulesFile(strings.Repeat("x", dom.MaxRuleIDLen+1))})
	if src = e.runSync(t, src); src.LastSyncStatus != dom.SyncFailed || !strings.Contains(string(src.LastSyncReport), "RULE_ID_TOO_LONG") {
		t.Fatalf("long rule id: %s %s", src.LastSyncStatus, src.LastSyncReport)
	}
	// The rule namespace never changes.
	if _, err := e.db.ExecContext(ctx, `UPDATE content_sources SET rule_namespace = 'other' WHERE tenant_id = $1 AND id = $2`,
		e.tenantA.String(), src.ID.String()); err == nil {
		t.Fatal("rule_namespace changed")
	}
	e.git.err = fmt.Errorf("auth required")
	src = e.runSync(t, src)
	if src.LastSyncStatus != dom.SyncFailed || src.ConsecutiveFailures != 3 {
		t.Fatalf("fetch failure: %s %d", src.LastSyncStatus, src.ConsecutiveFailures)
	}

	// Test persists nothing.
	e.git.set(sha('2'), map[string]string{"a.yaml": rulesFile("r1", "r2", "r3")})
	rep, err := e.svc.Test(ctx, e.actor(e.tenantA, e.user1), app.TestInput{Kind: "semgrep-rules", URL: "https://git.example.com/x.git", Ref: "v1.0", Token: "ghp_0123456789abcdef"})
	if err != nil || rep.Rules != 3 || rep.Commit != sha('2') {
		t.Fatalf("test: %+v %v", rep, err)
	}
	if e.git.last.Username != "x-access-token" {
		t.Fatalf("default username for a GitHub token: %q", e.git.last.Username)
	}
	if n := len(e.snapshots(t, src)); n != 0 {
		t.Fatalf("test stored %d snapshots", n)
	}
	// The instance limit of Test calls applies.
	var lastErr error
	for i := 0; i < app.TestCallsPerHour+1; i++ {
		_, lastErr = e.svc.Test(ctx, e.actor(e.tenantA, e.user1), app.TestInput{SourceID: &src.ID})
	}
	if !errors.Is(lastErr, dom.ErrTooManyRequests) {
		t.Fatalf("test rate limit: %v", lastErr)
	}
}

func TestRuleSources_Webhook_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-hook", func(in *app.CreateInput) { zero := 0; in.SyncIntervalMin = &zero })
	if _, err := e.db.ExecContext(ctx, `UPDATE content_sources SET sync_requested_at = NULL WHERE tenant_id = $1 AND id = $2`, e.tenantA.String(), src.ID.String()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.HandleWebhook(ctx, src.ID, "anything"); !errors.Is(err, app.ErrWebhookRejected) {
		t.Fatalf("webhook without a secret: %v", err)
	}
	secret, err := e.svc.RotateWebhookSecret(ctx, e.actor(e.tenantA, e.user1), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.HandleWebhook(ctx, src.ID, secret+"x"); !errors.Is(err, app.ErrWebhookRejected) {
		t.Fatalf("wrong secret: %v", err)
	}
	if err := e.svc.HandleWebhook(ctx, shared.NewID(), secret); !errors.Is(err, app.ErrWebhookRejected) {
		t.Fatalf("unknown source: %v", err)
	}
	if err := e.svc.HandleWebhook(ctx, src.ID, secret); err != nil {
		t.Fatal(err)
	}
	got, _ := e.repo.Get(ctx, e.tenantA, src.ID)
	if got.SyncRequestedAt == nil {
		t.Fatal("the webhook did not queue a sync")
	}
	var stored string
	_ = e.db.QueryRowContext(ctx, `SELECT webhook_secret_hash FROM content_sources WHERE tenant_id = $1 AND id = $2`, e.tenantA.String(), src.ID.String()).Scan(&stored)
	if stored == "" || strings.Contains(stored, secret) {
		t.Fatal("the webhook secret is stored in clear")
	}
	// Feature denied: calls are refused, the secret cannot be rotated.
	e.lim.denied[limits.FeatureContentWebhook] = true
	if err := e.svc.HandleWebhook(ctx, src.ID, secret); !errors.Is(err, app.ErrWebhookRejected) {
		t.Fatalf("webhook with the feature denied: %v", err)
	}
	var fd *limits.ErrFeatureDenied
	if _, err := e.svc.RotateWebhookSecret(ctx, e.actor(e.tenantA, e.user1), src.ID); !errors.As(err, &fd) {
		t.Fatalf("rotate with the feature denied: %v", err)
	}
}

func TestRuleSources_Limits_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var lr *limits.ErrLimitReached
	var fd *limits.ErrFeatureDenied

	// content_sources: no row is unlimited; over the limit is refused; a
	// lookup error refuses additions.
	e.create(t, "lim-1", nil)
	e.lim.limits[limits.ContentSources], e.lim.used[limits.ContentSources] = 1, 1
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "lim-2", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/x.git", Ref: "main"}); !errors.As(err, &lr) || lr.Key != limits.ContentSources {
		t.Fatalf("over content_sources: %v", err)
	}
	delete(e.lim.limits, limits.ContentSources)
	e.lim.broken = true
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "lim-3", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/x.git", Ref: "main"}); err == nil {
		t.Fatal("create with an unreadable limit succeeded")
	}
	e.lim.broken = false

	// content_sync_floor_minutes: a schedule under the floor is refused;
	// the instance floor of 5 minutes always applies.
	e.lim.limits[limits.ContentSyncFloorMinutes] = 60
	thirty, three := 30, 3
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "lim-4", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/x.git", Ref: "main", SyncIntervalMin: &thirty}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("schedule under the floor: %v", err)
	}
	delete(e.lim.limits, limits.ContentSyncFloorMinutes)
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "lim-5", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/x.git", Ref: "main", SyncIntervalMin: &three}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("schedule under the instance floor: %v", err)
	}

	// Features at their seams.
	e.lim.denied[limits.FeatureContentReviewPolicy] = true
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "lim-6", Name: "x", Kind: "semgrep-rules", URL: "https://git.example.com/x.git", Ref: "main", Policy: "review"}); !errors.As(err, &fd) {
		t.Fatalf("review policy denied: %v", err)
	}
	e.private = true
	e.lim.denied[limits.FeatureContentPrivateGit] = true
	if _, err := e.svc.Create(ctx, e.actor(e.tenantA, e.user1), app.CreateInput{Slug: "lim-7", Name: "x", Kind: "semgrep-rules", URL: "https://git.internal.example/x.git", Ref: "main"}); !errors.As(err, &fd) || fd.Feature != limits.FeatureContentPrivateGit {
		t.Fatalf("private host denied: %v", err)
	}
	e.private = false

	// content_snapshot_max_mb and content_storage_mb refuse a sync; the
	// last promoted snapshot stays.
	src := e.create(t, "lim-8", nil)
	e.git.set(sha('3'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	if src.CurrentSnapshotID == nil {
		t.Fatalf("first sync: %s", src.LastSyncError)
	}
	kept := *src.CurrentSnapshotID
	e.lim.limits[limits.ContentSnapshotMaxMB] = 0
	e.git.set(sha('4'), map[string]string{"a.yaml": rulesFile("r1", "r2")})
	src = e.runSync(t, src)
	if src.LastSyncStatus != dom.SyncFailed || !src.CurrentSnapshotID.Equals(kept) || !strings.Contains(src.LastSyncError, "content_snapshot_max_mb") {
		t.Fatalf("over content_snapshot_max_mb: %s %q", src.LastSyncStatus, src.LastSyncError)
	}
	delete(e.lim.limits, limits.ContentSnapshotMaxMB)
	e.lim.limits[limits.ContentStorageMB], e.lim.used[limits.ContentStorageMB] = 1, 1
	src = e.runSync(t, src)
	if src.LastSyncStatus != dom.SyncFailed || !src.CurrentSnapshotID.Equals(kept) || !strings.Contains(src.LastSyncError, "content_storage_mb") {
		t.Fatalf("over content_storage_mb: %s %q", src.LastSyncStatus, src.LastSyncError)
	}
}

type offGuard struct{ off shared.ID }

func (g offGuard) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	return map[string]bool{"template_sources": tenantID == g.off.String()}
}

// An organization that turned the module off is not synced.
func TestRuleSources_ModuleOffSkipsSync_DB(t *testing.T) {
	e := newEnv(t)
	src := e.create(t, "acme-off", nil)
	e.svc.SetModuleGuard(offGuard{off: e.tenantA})
	e.git.set(sha('8'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	if e.git.calls != 0 || src.CurrentSnapshotID != nil || src.SyncRequestedAt != nil || src.ConsecutiveFailures != 0 {
		t.Fatalf("module off: fetched %d, current %v, requested %v, failures %d", e.git.calls, src.CurrentSnapshotID, src.SyncRequestedAt, src.ConsecutiveFailures)
	}
	e.svc.SetModuleGuard(offGuard{})
	if src = e.runSync(t, src); src.CurrentSnapshotID == nil {
		t.Fatalf("module on: %s", src.LastSyncError)
	}
}

// A tenant-hosted source is neither fetched by the platform nor counted
// against content_sources; snapshot usage counts only stored packs.
func TestRuleSources_TenantHostedNotFetchedOrCounted_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mirror := e.create(t, "acme-mirror", nil)
	hosted := e.create(t, "acme-hosted", nil)
	if _, err := e.db.ExecContext(ctx, `UPDATE content_sources SET storage_mode = 'tenant_hosted' WHERE tenant_id = $1 AND id = $2`,
		e.tenantA.String(), hosted.ID.String()); err != nil {
		t.Fatal(err)
	}
	e.git.set(sha('9'), map[string]string{"a.yaml": rulesFile("r1")})
	e.runSync(t, hosted)
	if e.git.calls != 1 { // the mirror source's first sync only
		t.Fatalf("fetches: %d", e.git.calls)
	}
	if got, _ := e.repo.Get(ctx, e.tenantA, mirror.ID); got.CurrentSnapshotID == nil {
		t.Fatal("mirror source not synced")
	}
	usage, err := postgres.NewLimitsRepository(e.db).Usage(ctx, e.tenantA, false)
	if err != nil {
		t.Fatal(err)
	}
	if usage[limits.ContentSources] != 1 || usage[limits.ContentStorageMB] != 1 {
		t.Fatalf("usage: sources %d storage %d", usage[limits.ContentSources], usage[limits.ContentStorageMB])
	}
}

func TestRuleSources_CollectGarbage_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-gc", nil)
	for i, c := range []byte{'5', '6', '7'} {
		e.git.set(sha(c), map[string]string{"a.yaml": rulesFile(fmt.Sprintf("r%d", i))})
		src = e.runSync(t, src)
	}
	list := e.snapshots(t, src)
	if len(list) != 3 {
		t.Fatalf("snapshots: %d", len(list))
	}
	var oldest *dom.Snapshot
	for _, sn := range list {
		if sn.State == dom.StateSuperseded {
			oldest = sn
		}
	}
	if oldest == nil {
		t.Fatalf("no superseded snapshot: %+v", list)
	}
	if _, err := e.db.ExecContext(ctx, `UPDATE content_source_snapshots SET created_at = now() - interval '2 days'
		WHERE tenant_id = $1 AND id = $2`, e.tenantA.String(), oldest.ID.String()); err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.CollectGarbage(ctx)
	if err != nil || n < 1 {
		t.Fatalf("collect: %d %v", n, err)
	}
	if got := len(e.snapshots(t, src)); got != 2 {
		t.Fatalf("after collection: %d snapshots", got)
	}
	var packs int
	_ = e.db.QueryRowContext(ctx, `SELECT count(*) FROM content_packs WHERE tenant_id = $1 AND id = $2`, e.tenantA.String(), oldest.ContentPackID.String()).Scan(&packs)
	if packs != 0 {
		t.Fatal("the collected snapshot's pack is still stored")
	}
}
