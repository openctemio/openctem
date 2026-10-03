package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type reactionDBFixture struct {
	db       *sql.DB
	repo     *CommentReactionRepository
	comments *FindingCommentRepository
	tenantID shared.ID
	finding  shared.ID
	users    []shared.ID
}

func newReactionDBFixture(t *testing.T, nUsers int) *reactionDBFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	f := &reactionDBFixture{db: db, repo: NewCommentReactionRepository(&DB{DB: db}),
		comments: NewFindingCommentRepository(&DB{DB: db}), tenantID: shared.NewID()}
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		f.tenantID.String(), "reactions-test", "react-"+f.tenantID.String())
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, f.tenantID.String()) })
	for i := range nUsers {
		u := shared.NewID()
		mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`,
			u.String(), "react-"+u.String()+"@example.test", fmt.Sprintf("User %02d", i))
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, u.String()) })
		f.users = append(f.users, u)
	}
	var assetID string
	if err := db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,$2,$3) RETURNING id`,
		f.tenantID.String(), "web-01", "domain").Scan(&assetID); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	f.finding = mustID(t, insertFinding(t, db, f.tenantID.String(), assetID, "reactions"))
	return f
}

func (f *reactionDBFixture) comment(t *testing.T, internal bool) shared.ID {
	t.Helper()
	c, err := vulnerability.NewFindingComment(f.tenantID, f.finding, f.users[0], "a comment")
	if err != nil {
		t.Fatal(err)
	}
	c.SetInternal(internal)
	if err := f.comments.Create(context.Background(), c); err != nil {
		t.Fatalf("create comment: %v", err)
	}
	return c.ID()
}

func TestCommentReactionRepository_AddRemoveSummaries(t *testing.T) {
	f := newReactionDBFixture(t, 7)
	ctx := context.Background()
	c1, c2 := f.comment(t, false), f.comment(t, true)

	add := func(c shared.ID, u int, e string) bool {
		t.Helper()
		ok, err := f.repo.Add(ctx, f.tenantID, c, f.users[u], e)
		if err != nil {
			t.Fatalf("add %s by %d: %v", e, u, err)
		}
		return ok
	}
	if !add(c1, 0, "🎉") || !add(c1, 1, "👍") || !add(c1, 2, "🎉") {
		t.Fatal("first adds must insert")
	}
	if add(c1, 0, "🎉") {
		t.Fatal("re-adding an existing reaction must be a no-op")
	}
	for u := 1; u < 7; u++ {
		add(c1, u, "👀")
	}
	add(c2, 3, "✅")

	got, err := f.repo.Summaries(ctx, f.tenantID, []shared.ID{c1, c2}, f.users[2])
	if err != nil {
		t.Fatal(err)
	}
	s1 := got[c1]
	if len(s1) != 3 || s1[0].Emoji != "🎉" || s1[1].Emoji != "👍" || s1[2].Emoji != "👀" {
		t.Fatalf("c1 order = %+v, want first-use order 🎉 👍 👀", s1)
	}
	if s1[0].Count != 2 || !s1[0].ReactedByMe || s1[1].ReactedByMe {
		t.Fatalf("c1 🎉/👍 = %+v / %+v", s1[0], s1[1])
	}
	if s1[2].Count != 6 || len(s1[2].SampleUsers) != vulnerability.ReactionSampleUsers ||
		s1[2].SampleUsers[0].ID != f.users[1] || s1[2].SampleUsers[0].Name != "User 01" {
		t.Fatalf("c1 👀 = %+v, want 6 with 5 earliest samples", s1[2])
	}
	if len(got[c2]) != 1 || got[c2][0].Emoji != "✅" {
		t.Fatalf("c2 = %+v", got[c2])
	}

	// Counts change, order does not: removing 🎉 reactions keeps 👍 second.
	if ok, err := f.repo.Remove(ctx, f.tenantID, c1, f.users[2], "🎉"); err != nil || !ok {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if ok, _ := f.repo.Remove(ctx, f.tenantID, c1, f.users[2], "🎉"); ok {
		t.Fatal("second remove must report nothing removed")
	}
	got, _ = f.repo.Summaries(ctx, f.tenantID, []shared.ID{c1}, f.users[2])
	if got[c1][0].Emoji != "🎉" || got[c1][0].Count != 1 || got[c1][0].ReactedByMe {
		t.Fatalf("after remove = %+v", got[c1])
	}

	// Another tenant sees nothing and cannot add.
	other := shared.NewID()
	got, _ = f.repo.Summaries(ctx, other, []shared.ID{c1}, f.users[2])
	if len(got) != 0 {
		t.Fatalf("other tenant saw %v", got)
	}
	if _, err := f.repo.Add(ctx, other, c1, f.users[0], "👍"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant add err = %v, want ErrNotFound", err)
	}

	// The trigger refuses a reaction whose tenant is not the comment's.
	mustExec(t, f.db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`, other.String(), "other", "react-o-"+other.String())
	t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, other.String()) })
	if _, err := f.db.ExecContext(ctx, `INSERT INTO comment_reactions (tenant_id, comment_id, user_id, emoji) VALUES ($1,$2,$3,'👍')`,
		other.String(), c1.String(), f.users[0].String()); err == nil {
		t.Fatal("trigger accepted a cross-tenant reaction")
	}

	// is_internal round-trips through the comment repository.
	cc, err := f.comments.GetByTenantAndID(ctx, f.tenantID, c2)
	if err != nil || !cc.IsInternal() {
		t.Fatalf("internal comment read back: %v internal=%v", err, cc != nil && cc.IsInternal())
	}
	list, err := f.comments.ListByFinding(ctx, f.finding)
	if err != nil || len(list) != 2 || list[0].IsInternal() || !list[1].IsInternal() {
		t.Fatalf("list internal flags wrong: %v", err)
	}
}

func TestCommentReactionRepository_CapsHoldUnderConcurrency(t *testing.T) {
	f := newReactionDBFixture(t, 30)
	ctx := context.Background()
	c := f.comment(t, false)

	// 30 people race to add 30 different emoji: exactly 20 may land.
	var wg sync.WaitGroup
	var mu sync.Mutex
	added, capped := 0, 0
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.repo.Add(ctx, f.tenantID, c, f.users[i], string(rune(0x1F600+i)))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, vulnerability.ErrReactionEmojiLimit):
				capped++
			case err != nil:
				t.Errorf("add %d: %v", i, err)
			case ok:
				added++
			}
		}()
	}
	wg.Wait()
	if added != vulnerability.MaxDistinctReactionsPerComment || capped != 10 {
		t.Fatalf("added=%d capped=%d, want 20 and 10", added, capped)
	}

	// One person racing 15 reactions on a fresh comment: exactly 10 land.
	c2 := f.comment(t, false)
	added, capped = 0, 0
	for i := range 15 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.repo.Add(ctx, f.tenantID, c2, f.users[0], string(rune(0x1F400+i)))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, vulnerability.ErrReactionUserLimit):
				capped++
			case err != nil:
				t.Errorf("add %d: %v", i, err)
			case ok:
				added++
			}
		}()
	}
	wg.Wait()
	if added != vulnerability.MaxReactionsPerUserPerComment || capped != 5 {
		t.Fatalf("per-user: added=%d capped=%d, want 10 and 5", added, capped)
	}
}
