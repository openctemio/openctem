package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Migration ticketing_issue_types moves the single issue type name into the
// finding and task entries and drops the old key; down restores it. The
// ticketing health is written per kind, only on the tenant's own row.
func TestTicketingIssueTypes_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "ticketing_issue_types", dir)
	v := testdb.MigrationVersion(t, dir, "ticketing_issue_types")
	testdb.Migrate(t, db, dir, v, v, true) // back to the old shape

	tenantA, tenantB := shared.NewID(), shared.NewID()
	for _, tid := range []shared.ID{tenantA, tenantB} {
		if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "t-"+tid.String()); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(tid shared.ID, name, category, config string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, auth_type, config)
			VALUES ($1, $2, $3, $4, 'jira', 'token', $5::jsonb)`, id.String(), tid.String(), name, category, config); err != nil {
			t.Fatal(err)
		}
		return id
	}
	withType := insert(tenantA, "jira-a", "ticketing", `{"ticketing":{"issue_type":" Security Finding ","project_key":"SEC"}}`)
	blank := insert(tenantA, "jira-b", "ticketing", `{"ticketing":{"issue_type":"","project_key":"SEC"}}`)
	noType := insert(tenantA, "jira-c", "ticketing", `{"ticketing":{"project_key":"SEC"}}`)
	other := insert(tenantB, "jira-d", "ticketing", `{"ticketing":{"issue_type":"Bug"}}`)

	testdb.Migrate(t, db, dir, v, v, false)

	ticketing := func(id shared.ID) map[string]any {
		t.Helper()
		var raw []byte
		if err := db.QueryRow(`SELECT config -> 'ticketing' FROM integrations WHERE id = $1`, id.String()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	got := ticketing(withType)
	types, _ := got["issue_types"].(map[string]any)
	if _, old := got["issue_type"]; old || got["project_key"] != "SEC" ||
		types["finding"].(map[string]any)["name"] != "Security Finding" || types["task"].(map[string]any)["name"] != "Security Finding" {
		t.Fatalf("migrated %v", got)
	}
	if got := ticketing(blank); got["issue_type"] != nil || got["issue_types"] != nil || got["project_key"] != "SEC" {
		t.Fatalf("blank %v", got)
	}
	if got := ticketing(noType); len(got) != 1 {
		t.Fatalf("untouched %v", got)
	}
	if got := ticketing(other); got["issue_types"] == nil {
		t.Fatalf("other tenant %v", got)
	}

	// Down restores the single name.
	testdb.Migrate(t, db, dir, v, v, true)
	if got := ticketing(withType); got["issue_type"] != "Security Finding" || got["issue_types"] != nil {
		t.Fatalf("down %v", got)
	}
	testdb.Migrate(t, db, dir, v, v, false)

	// Ticketing health: per kind, tenant-scoped, cleared only where present.
	repo := NewIntegrationRepository(&DB{DB: db})
	ctx := context.Background()
	health := func(id shared.ID) string {
		t.Helper()
		var s *string
		if err := db.QueryRow(`SELECT metadata -> 'ticketing_health' FROM integrations WHERE id = $1`, id.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return *s
	}
	if err := repo.RecordTicketingHealth(ctx, tenantA, withType, "task", map[string]any{"fields": []string{"issuetype"}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordTicketingHealth(ctx, tenantA, withType, "finding", map[string]any{"fields": []string{"customfield_1"}}); err != nil {
		t.Fatal(err)
	}
	if h := health(withType); h != `{"task": {"fields": ["issuetype"]}, "finding": {"fields": ["customfield_1"]}}` {
		t.Fatalf("health %s", h)
	}
	// Another tenant cannot write or clear it.
	_ = repo.RecordTicketingHealth(ctx, tenantB, withType, "task", nil)
	_ = repo.RecordTicketingHealth(ctx, tenantB, withType, "epic", map[string]any{"x": 1})
	if h := health(withType); h != `{"task": {"fields": ["issuetype"]}, "finding": {"fields": ["customfield_1"]}}` {
		t.Fatalf("cross-tenant write reached the row: %s", h)
	}
	if err := repo.RecordTicketingHealth(ctx, tenantA, withType, "task", nil); err != nil {
		t.Fatal(err)
	}
	if h := health(withType); h != `{"finding": {"fields": ["customfield_1"]}}` {
		t.Fatalf("after clear %s", h)
	}
	// Clearing a kind with nothing recorded changes nothing.
	if err := repo.RecordTicketingHealth(ctx, tenantA, noType, "task", nil); err != nil || health(noType) != "" {
		t.Fatalf("clear without health: %v %s", err, health(noType))
	}
}
