package postgres

// Migration 001012 (research doc 21b C2 / L-15): activity rows that recorded
// the name and email of an assignee outside the row's organization get a
// neutral label instead; same-organization rows, ids and timestamps are
// untouched. Replayed in a rolled-back transaction as the migrator.

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestForeignAssigneeScrubMigration(t *testing.T) {
	ctx := context.Background()
	up, err := os.ReadFile("../../../migrations/001012_scrub_foreign_assignee_pii.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/001012_scrub_foreign_assignee_pii.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	db := openGroupsDB(t)
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	testdb.LockForDDL(t, ctx, tx, "finding_activities")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	user := func(tenants ...shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, id.String(), "pii-"+id.String()+"@scrub.test", "Name "+id.String())
		for _, tn := range tenants {
			exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id.String(), tn.String())
		}
		return id
	}
	member, outsider := user(tenant), user(other)

	asset := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, asset.String(), tenant.String(), "scrub-"+asset.String())
	finding := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
			VALUES ($1, $2, $3, 'manual', 'x', 'high', 'm', $4)`, id.String(), tenant.String(), asset.String(), "scrub-"+id.String())
		return id
	}
	base := time.Now().Add(-time.Hour)
	n := 0
	activity := func(f shared.ID, typ string, changes map[string]any, message string) shared.ID {
		n++
		id := shared.NewID()
		b, _ := json.Marshal(changes)
		exec(`INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, changes, message, created_at)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7)`, id.String(), tenant.String(), f.String(), typ, string(b), message,
			base.Add(time.Duration(n)*time.Minute))
		return id
	}
	assigned := func(f, u shared.ID, message string) shared.ID {
		return activity(f, "assigned", map[string]any{
			"assignee_id": u.String(), "assignee_name": "Name " + u.String(), "assignee_email": "pii-" + u.String() + "@scrub.test",
		}, message)
	}

	fForeign, fMember := finding(), finding()
	foreignAssigned := assigned(fForeign, outsider, "Assigned to Name "+outsider.String())
	foreignUnassigned := activity(fForeign, "unassigned", map[string]any{"previous_assignee_name": "Name " + outsider.String()}, "")
	memberAssigned := assigned(fMember, member, "Assigned to Name "+member.String())
	memberUnassigned := activity(fMember, "unassigned", map[string]any{"previous_assignee_name": "Name " + member.String()}, "")
	// A foreign assignment followed by a member assignment: the unassign
	// refers to the member (the latest earlier assignment) and is kept.
	fMixed := finding()
	assigned(fMixed, outsider, "")
	assigned(fMixed, member, "")
	mixedUnassigned := activity(fMixed, "unassigned", map[string]any{"previous_assignee_name": "Name " + member.String()}, "")

	type row struct {
		changes   map[string]any
		message   sql.NullString
		createdAt time.Time
		finding   string
	}
	read := func(id shared.ID) row {
		t.Helper()
		var r row
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT changes, message, created_at, finding_id::text FROM finding_activities WHERE id = $1`, id.String()).
			Scan(&raw, &r.message, &r.createdAt, &r.finding); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &r.changes)
		return r
	}
	before := map[shared.ID]row{}
	for _, id := range []shared.ID{foreignAssigned, foreignUnassigned, memberAssigned, memberUnassigned, mixedUnassigned} {
		before[id] = read(id)
	}

	exec(string(up))
	exec(string(up)) // idempotent
	const label = "Former assignee (not in this organization)"

	got := read(foreignAssigned)
	if got.changes["assignee_name"] != label || got.changes["assignee_email"] != nil {
		t.Errorf("foreign assigned row = %v, want the label and no email", got.changes)
	}
	if got.changes["assignee_id"] != outsider.String() || got.message.Valid {
		t.Errorf("foreign assigned row: id %v (want kept), message %v (want cleared, it quoted the name)", got.changes["assignee_id"], got.message)
	}
	if got.createdAt != before[foreignAssigned].createdAt || got.finding != before[foreignAssigned].finding {
		t.Error("foreign assigned row: timestamp or finding changed")
	}
	if got := read(foreignUnassigned); got.changes["previous_assignee_name"] != label {
		t.Errorf("foreign unassigned row = %v, want the label", got.changes)
	}
	for name, id := range map[string]shared.ID{"member assigned": memberAssigned, "member unassigned": memberUnassigned, "unassign after a member assignment": mixedUnassigned} {
		got, want := read(id), before[id]
		gb, _ := json.Marshal(got.changes)
		wb, _ := json.Marshal(want.changes)
		if string(gb) != string(wb) || got.message != want.message || got.createdAt != want.createdAt {
			t.Errorf("%s changed: %s / %v, want %s / %v", name, gb, got.message, wb, want.message)
		}
	}

	exec(string(down)) // one-way: runs, restores nothing
	if got := read(foreignAssigned); got.changes["assignee_email"] != nil {
		t.Error("the down migration brought the email back")
	}
}
