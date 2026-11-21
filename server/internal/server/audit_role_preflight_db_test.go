package server

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The start-up check tells the schema owner (one role for migrations and the
// API: audit history is not protected from the API's credentials) from the
// least-privilege API role.
func TestAPIRoleOwnsAuditLog_DB(t *testing.T) {
	ctx := context.Background()
	if owns, err := apiRoleOwnsAuditLog(ctx, nil); err != nil || owns {
		t.Fatalf("nil DB: got (%v, %v), want (false, nil)", owns, err)
	}
	warnAPIRoleOwnsAuditLog(ctx, nil, logger.NewNop())

	mig := testdb.OpenMigrator(t)
	if owns, err := apiRoleOwnsAuditLog(ctx, mig); err != nil || !owns {
		t.Fatalf("schema owner: got (%v, %v), want (true, nil)", owns, err)
	}
	if testdb.MigratorURL() == testdb.URL() {
		return // one role locally: nothing more to tell apart
	}
	app, err := sql.Open("postgres", testdb.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	if owns, err := apiRoleOwnsAuditLog(ctx, app); err != nil || owns {
		t.Fatalf("API role: got (%v, %v), want (false, nil)", owns, err)
	}
}
