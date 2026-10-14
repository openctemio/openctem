package postgres

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/ctis/politeness"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every command gets its host keys at the one create choke point
// (command.AssignHostKeys, research/130). Requires DATABASE_URL.

func storedHostKeys(ctx context.Context, t *testing.T, repo *CommandRepository, id shared.ID) (column, payload []string) {
	t.Helper()
	var raw json.RawMessage
	if err := repo.db.QueryRowContext(ctx, `SELECT host_keys, payload FROM commands WHERE id = $1`, id.String()).
		Scan(pq.Array(&column), &raw); err != nil {
		t.Fatal(err)
	}
	var p struct {
		HostKeys []string `json:"host_keys"`
	}
	_ = json.Unmarshal(raw, &p)
	return column, p.HostKeys
}

// The live incident, replayed: a workflow's httpx chunk holds 3 hosts; a
// quick scan's nuclei command (built without host keys, as the
// single-scanner path builds it) on 2 of them is not offered or claimable
// while httpx holds them, and a nuclei command on other hosts fills the
// sensor's free slot instead.
func TestCommandHostKeys_QuickScanHeldBehindWorkflowChunk(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: []string{"httpx", "nuclei"}})

	httpx := createHostChunk(ctx, t, cmds, tenant, "a.example.com", "b.example.com", "c.example.com")
	if ok, err := cmds.ClaimForSensor(ctx, tenant, httpx, s.String()); err != nil || !ok {
		t.Fatalf("httpx chunk not claimed: %v %v", ok, err)
	}

	nuclei := func(targets ...string) shared.ID {
		raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "scanner_name": "nuclei", "targets": targets,
			"scan_run_id": shared.NewID().String(), "step_key": "quick_scan", "targets_per_job": 10})
		cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmds.Create(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		return cmd.ID
	}
	busy := nuclei("https://a.example.com/", "https://b.example.com/login")
	free := nuclei("https://d.example.com/")

	col, sent := storedHostKeys(ctx, t, cmds, busy)
	want := politeness.Keys([]string{"https://a.example.com/", "https://b.example.com/login"}, "")
	if !slices.Equal(col, want) || !slices.Equal(sent, want) {
		t.Fatalf("stored keys column=%v payload=%v, want %v", col, sent, want)
	}

	got := polledIDs(ctx, t, cmds, tenant, s)
	if got[busy] || !got[free] {
		t.Fatalf("offered %v: want the free nuclei command, not the one on httpx's hosts", got)
	}
	claimed, err := cmds.ClaimManyForSensor(ctx, tenant, s, nil, []shared.ID{busy, free})
	if err != nil || len(claimed) != 1 || claimed[0] != free {
		t.Fatalf("claim-N took %v (%v); want only the free command", claimed, err)
	}

	// httpx ends: the held nuclei command is offered.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, httpx.String()); err != nil {
		t.Fatal(err)
	}
	if !polledIDs(ctx, t, cmds, tenant, s)[busy] {
		t.Fatal("nuclei command not offered once its hosts were free")
	}
}

func TestBackfillPendingHostKeys(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)

	insert := func(status, payload string) shared.ID {
		id := shared.NewID()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', $3, $4)`,
			id.String(), tenant.String(), status, payload); err != nil {
			t.Fatal(err)
		}
		return id
	}
	pending := insert("pending", `{"scanner":"nuclei","targets":["https://a.example.com/","b.example.com"]}`)
	noHost := insert("pending", `{"scanner":"nuclei","targets":[]}`)
	running := insert("running", `{"scanner":"nuclei","targets":["c.example.com"]}`)
	passive := insert("pending", `{"scanner":"subfinder","targets":["d.example.com"],"host_keys":[]}`)

	if _, err := BackfillPendingHostKeys(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	col, sent := storedHostKeys(ctx, t, cmds, pending)
	want := politeness.Keys([]string{"https://a.example.com/", "b.example.com"}, "")
	if !slices.Equal(col, want) || sent != nil {
		t.Fatalf("backfilled column=%v payload=%v, want column %v and the payload untouched", col, sent, want)
	}
	for _, id := range []shared.ID{noHost, running, passive} {
		if col, _ := storedHostKeys(ctx, t, cmds, id); len(col) != 0 {
			t.Fatalf("%s got keys %v", id, col)
		}
	}
	var payload string
	if err := sqlDB.QueryRowContext(ctx, `SELECT payload::text FROM commands WHERE id = $1`, pending.String()).Scan(&payload); err != nil ||
		payload != `{"scanner": "nuclei", "targets": ["https://a.example.com/", "b.example.com"]}` {
		t.Fatalf("the backfill rewrote the payload: %s (%v)", payload, err)
	}
	// Marked done: a second pass changes nothing.
	if n, err := BackfillPendingHostKeys(ctx, sqlDB); err != nil || n != 0 {
		t.Fatalf("second pass updated %d (%v)", n, err)
	}
}

// Every command is created through CommandRepository.Create (which assigns
// its host keys) or copies a row that was: a new INSERT INTO commands
// elsewhere would bypass the choke point.
func TestCommandsInsertedOnlyThroughTheChokePoint(t *testing.T) {
	allowed := map[string]bool{
		"command_repository.go":  true, // Create: AssignHostKeys
		"command_follow_up.go":   true, // NewFollowUp: keys of the remaining targets
		"command_window_hold.go": true, // copies the held row's keys and payload
		"command_host_split.go":  true, // SplitHostBusy: keys of the waiting targets, within the row's
	}
	var found []string
	err := filepath.WalkDir("../..", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "INSERT INTO commands") && !allowed[filepath.Base(path)] {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("commands inserted outside CommandRepository.Create: %v", found)
	}
}
