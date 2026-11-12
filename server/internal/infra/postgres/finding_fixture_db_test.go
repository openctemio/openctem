package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Fixtures shared by the DB tests of this package.

func insertFinding(t *testing.T, db *sql.DB, tenantID, assetID, msg string) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(context.Background(),
		`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		 VALUES ($1,$2,'sca','trivy',$3,'critical',$4,'new') RETURNING id`,
		tenantID, assetID, msg, "fp-"+shared.NewID().String()).Scan(&id); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

func mustID(t *testing.T, s string) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(s)
	if err != nil {
		t.Fatalf("parse id %q: %v", s, err)
	}
	return id
}
