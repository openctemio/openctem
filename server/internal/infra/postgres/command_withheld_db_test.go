package postgres

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func withheldOf(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) string {
	t.Helper()
	var r sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT withheld_reason FROM commands WHERE id = $1`, id.String()).Scan(&r); err != nil {
		t.Fatal(err)
	}
	return r.String
}

// A sensor's poll that the grant keeps from a command records the reason
// on the command, and the placement explainer names it. RecordWithheld
// writes only pending commands of the caller's tenant.
func TestWithheld_PollRecordsAndPlacementNames(t *testing.T) {
	f := newPlacementFixture(t)
	db := f.repo.db.DB
	grantNarrow := f.sensors[4] // grant allows httpx only
	cmd := f.cmds["unzoned"]
	if f.polled(t, grantNarrow, cmd) {
		t.Fatal("the narrow grant handed out a nuclei command")
	}
	if got := withheldOf(f.ctx, t, db, cmd); got != "grant_tools" {
		t.Fatalf("withheld_reason %q, want grant_tools", got)
	}
	p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if p.Withheld != "grant_tools" || p.WithheldAt == nil {
		t.Fatalf("placement withheld %q at %v, want grant_tools with a time", p.Withheld, p.WithheldAt)
	}

	// Another tenant cannot write the tenant's command.
	other := seedTestTenant(f.ctx, t, db)
	if err := f.repo.RecordWithheld(f.ctx, other, map[shared.ID]string{cmd: "grant_credentials"}); err != nil {
		t.Fatal(err)
	}
	if got := withheldOf(f.ctx, t, db, cmd); got != "grant_tools" {
		t.Fatalf("another tenant overwrote the reason: %q", got)
	}
	// A command no longer pending is not written.
	done := f.cmds["later"]
	if _, err := db.ExecContext(f.ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, done.String()); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.RecordWithheld(f.ctx, f.tenant, map[shared.ID]string{done: "intensity"}); err != nil {
		t.Fatal(err)
	}
	if got := withheldOf(f.ctx, t, db, done); got != "" {
		t.Fatalf("a completed command got a withheld reason: %q", got)
	}
	// A different reason replaces the recorded one at once.
	if err := f.repo.RecordWithheld(f.ctx, f.tenant, map[shared.ID]string{cmd: "intensity"}); err != nil {
		t.Fatal(err)
	}
	if got := withheldOf(f.ctx, t, db, cmd); got != "intensity" {
		t.Fatalf("withheld_reason %q, want the newer reason", got)
	}
}

// A run nobody claimed because a sensor's gate withheld its work ends with
// the reason in its message (the prod case: "withheld by sensor
// permissions: credentials"), and its task still carries the code.
func TestAbortUnclaimedRuns_NamesWithheldReason(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewScanRunRepository(&DB{DB: db})
	cmds := NewCommandRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)
	withheld := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", 2*time.Hour)
	withheldCmd := seedRunCommand(ctx, t, db, tenantID, withheld, "pending", false, 0)
	plain := seedActiveRun(ctx, t, db, tenantID, scanID, "manual", 2*time.Hour)
	seedRunCommand(ctx, t, db, tenantID, plain, "pending", false, 0)
	if err := cmds.RecordWithheld(ctx, tenantID, map[shared.ID]string{withheldCmd: "grant_credentials"}); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.AbortUnclaimedRuns(ctx, 4*time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, msg := runStatus(ctx, t, db, withheld)
	if !strings.Contains(msg.String, "withheld by sensor permissions: credentials") {
		t.Fatalf("run message %q does not name the refusal", msg.String)
	}
	var stepMsg string
	if err := db.QueryRowContext(ctx, `SELECT error_message FROM scan_run_steps WHERE scan_run_id = $1`, withheld.String()).Scan(&stepMsg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stepMsg, "credentials") {
		t.Fatalf("step message %q does not name the refusal", stepMsg)
	}
	if _, msg := runStatus(ctx, t, db, plain); !strings.Contains(msg.String, "check that a sensor") {
		t.Fatalf("a run with no refusal keeps the generic hint: %q", msg.String)
	}
	tasks, _, err := cmds.ListRunTasks(ctx, tenantID, withheld, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].WithheldReason != "grant_credentials" {
		t.Fatalf("tasks %+v, want the failed task to keep grant_credentials", tasks)
	}
}

// The SQL phrase of every withheld code is command.WithheldText's.
func TestWithheldTextSQL_MatchesGo(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	codes := []string{"grant_credentials", "grant_tier_ceiling", "brand_new_code"}
	for c := range command.WithheldTexts() {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT `+withheldTextSQL("$1::text"), c).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if want := command.WithheldText(c); got != want {
			t.Errorf("%s: SQL %q, Go %q", c, got, want)
		}
	}
}
