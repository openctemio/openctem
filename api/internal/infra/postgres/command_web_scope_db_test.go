package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// recordingGuard records the commands it saw and answers with err.
type recordingGuard struct {
	seen []shared.ID
	err  error
}

func (g *recordingGuard) GuardCreate(_ context.Context, cmd *command.Command) error {
	g.seen = append(g.seen, cmd.ID)
	if g.err == nil {
		cmd.Payload = json.RawMessage(`{"scanner":"nuclei","web_scope":{"deny_paths":["/admin"]}}`)
	}
	return g.err
}

func newWebTestCommand(t *testing.T, tenant shared.ID, tool string) *command.Command {
	t.Helper()
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal,
		json.RawMessage(`{"scanner":"`+tool+`","targets":["https://app.example.com"]}`))
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func storedPayload(ctx context.Context, t *testing.T, db *DB, id shared.ID) (string, bool) {
	t.Helper()
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT payload FROM commands WHERE id = $1`, id.String()).Scan(&raw); err != nil {
		return "", false
	}
	return string(raw), true
}

// SECURITY: Create is the choke point. Every command passes the guard; the
// payload it completes is what is stored; a refusal stores nothing.
func TestCommandCreate_RunsTheGuard(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	tenant := seedTestTenant(ctx, t, sqlDB)
	repo := NewCommandRepository(db)
	g := &recordingGuard{}
	repo.SetCreateGuard(g)

	cmd := newWebTestCommand(t, tenant, "nuclei")
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	if got, _ := storedPayload(ctx, t, db, cmd.ID); !strings.Contains(got, `"deny_paths": ["/admin"]`) {
		t.Fatalf("stored payload %s, want the guard's web scope", got)
	}
	g.err = errors.New("refused")
	refused := newWebTestCommand(t, tenant, "nuclei")
	if err := repo.Create(ctx, refused); err == nil {
		t.Fatal("a refused command was stored")
	}
	if _, ok := storedPayload(ctx, t, db, refused.ID); ok {
		t.Fatal("a refused command is in the table")
	}
	if len(g.seen) != 2 {
		t.Fatalf("guard saw %d command(s), want 2", len(g.seen))
	}
}

// SECURITY: without a guard, a web job of a tenant with a path exclusion is
// refused (fail closed); one of another tenant without one, and a job
// without web requests, are stored.
func TestCommandCreate_UnguardedWebJob(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	ruled := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, path_prefix, reason, status, approved_by, approved_at, created_by)
		 VALUES ($1, 'path', 'app.example.com/admin', '/admin', 'test', 'active', 'approver', NOW(), 'requester')`,
		ruled.String()); err != nil {
		t.Fatal(err)
	}
	repo := NewCommandRepository(db)
	for _, tool := range []string{"nuclei", "katana", "zap"} {
		if err := repo.Create(ctx, newWebTestCommand(t, ruled, tool)); !errors.Is(err, command.ErrWebScopeUnwired) {
			t.Fatalf("%s for a tenant with a path exclusion: err = %v, want ErrWebScopeUnwired", tool, err)
		}
	}
	// Unguarded, the organization's tool facts are not read: any job that
	// names a tool may be a web job and is refused (fail closed).
	if err := repo.Create(ctx, newWebTestCommand(t, ruled, "httpx")); !errors.Is(err, command.ErrWebScopeUnwired) {
		t.Fatalf("httpx for a tenant with a path exclusion, unguarded: err = %v, want ErrWebScopeUnwired", err)
	}
	if err := repo.Create(ctx, newWebTestCommand(t, other, "nuclei")); err != nil {
		t.Fatalf("another tenant's rule refused this tenant's job: %v", err)
	}
}

var insertCommandsRe = regexp.MustCompile(`(?i)insert\s+into\s+commands\b`)

// SECURITY: a guard against a new dispatch path that skips the choke
// point. Commands are inserted only by Create (guarded), by the window
// hold's split, which copies a stored command's guarded payload, and by the
// follow-up of unfinished targets, which passes the guard itself.
func TestCommandInserts_OnlyThroughTheGuard(t *testing.T) {
	allowed := map[string]bool{"command_repository.go": true, "command_window_hold.go": true, "command_follow_up.go": true}
	root := filepath.Join("..", "..", "..")
	found := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root {
			if n := d.Name(); n == "tests" || n == "migrations" || n == "docs" || strings.HasPrefix(n, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !insertCommandsRe.Match(src) {
			return nil
		}
		found++
		if !allowed[filepath.Base(path)] {
			t.Errorf("%s inserts commands outside CommandRepository.Create: route it through Create so the web scope guard runs", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < len(allowed) {
		t.Fatalf("found %d file(s) inserting commands, want at least %d: the walk missed the source tree", found, len(allowed))
	}
}
