package postgres

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// TestAdminAuditChangesOnly_DB: the "changes" view of the administrator audit
// log leaves out successful reads and write-ahead rows, and keeps writes,
// sign-ins, refused reads and rows without a request (host commands). The
// full list still returns every row.
func TestAdminAuditChangesOnly_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "admin_audit_changes", "../../../migrations")
	ctx := context.Background()
	repo := NewAuditLogRepository(&DB{DB: db})

	write := func(action, method string, success bool) {
		t.Helper()
		l := &admin.AuditLog{ID: shared.NewID(), AdminEmail: "root@example.com", Action: action,
			RequestMethod: method, Success: success, CreatedAt: time.Now(), Severity: "info"}
		if err := repo.Create(ctx, l); err != nil {
			t.Fatalf("create %s: %v", action, err)
		}
	}
	write("organization.view", "GET", true)
	write("platform_user.view", "GET", true)
	write(admin.AuditActionWriteStarted, "POST", true)
	write("organization.suspend", "POST", true)
	write("console.login", "POST", true)
	write("console.elevated", "POST", true)
	write("organization.view_refused", "GET", false)
	write("bootstrap.admin_created", "", true)

	list := func(changes bool) []string {
		t.Helper()
		res, err := repo.List(ctx, admin.AuditLogFilter{ChangesOnly: changes}, pagination.Pagination{Page: 1, PerPage: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		out := make([]string, 0, len(res.Data))
		for _, l := range res.Data {
			out = append(out, l.Action)
		}
		sort.Strings(out)
		return out
	}

	got := list(true)
	want := []string{"bootstrap.admin_created", "console.elevated", "console.login",
		"organization.suspend", "organization.view_refused"}
	if len(got) != len(want) {
		t.Fatalf("changes view = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("changes view = %v, want %v", got, want)
		}
	}
	if all := list(false); len(all) != 8 {
		t.Fatalf("full list has %d rows, want 8: %v", len(all), all)
	}
}
