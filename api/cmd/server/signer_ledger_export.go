package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// runSignerLedgerExport writes the scope in effect of every organization as
// a job-signer ledger snapshot (RFC-040 P2 bootstrap ceremony,
// docs/architecture/job-signing.md "Scope ledger"), then exits. The file is
// created 0600 and never overwritten; its SHA-256 is printed so the
// operator can compare it with what `openctem-signer ledger import`
// reports.
//
//	docker compose exec api ./server -signer-ledger-export /tmp/ledger.json
func runSignerLedgerExport(ctx context.Context, db *postgres.DB, path string, w io.Writer, log *logger.Logger) int {
	exp, err := buildLedgerExport(ctx, db, log)
	if err != nil {
		_, _ = fmt.Fprintf(w, "ledger export failed: %v\n", err)
		return 1
	}
	raw, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(w, "ledger export failed: %v\n", err)
		return 1
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied output path
	if err != nil {
		_, _ = fmt.Fprintf(w, "ledger export failed: %v\n", err)
		return 1
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_, _ = fmt.Fprintf(w, "ledger export failed: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
		_, _ = fmt.Fprintf(w, "ledger export failed: %v\n", err)
		return 1
	}
	entries, exclusions, templates := 0, 0, 0
	for _, t := range exp.Tenants {
		entries += len(t.Entries)
		exclusions += len(t.Exclusions)
		templates += len(t.Templates)
	}
	sum := sha256.Sum256(raw)
	_, _ = fmt.Fprintf(w, "wrote %s: sha256:%s, %d organizations, %d entries, %d exclusions, %d templates\n",
		path, hex.EncodeToString(sum[:]), len(exp.Tenants), entries, exclusions, templates)
	return 0
}

func buildLedgerExport(ctx context.Context, db *postgres.DB, log *logger.Logger) (jobsign.LedgerExport, error) {
	exp := jobsign.LedgerExport{Kind: jobsign.SnapshotKind, CreatedAt: time.Now().UTC(), Tenants: []jobsign.LedgerSnapshot{}}
	rows, err := db.QueryContext(ctx, `
		SELECT tenant_id FROM scope_targets WHERE status = 'active'
		UNION
		SELECT tenant_id FROM scope_exclusions WHERE status = 'active'
		UNION
		SELECT tenant_id FROM scanner_templates WHERE status = 'active' AND ledger_sha256 IS NOT NULL
		ORDER BY 1`)
	if err != nil {
		return exp, fmt.Errorf("list organizations with scope: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return exp, err
		}
		tenants = append(tenants, id)
	}
	if err := rows.Err(); err != nil {
		return exp, err
	}
	svc := scope.NewService(postgres.NewScopeTargetRepository(db), postgres.NewScopeExclusionRepository(db), nil, log)
	svc.SetLedgerTemplates(app.NewScannerTemplateService(postgres.NewScannerTemplateRepository(db), "", log))
	for _, id := range tenants {
		snap, err := svc.LedgerSnapshot(ctx, id)
		if err != nil {
			return exp, fmt.Errorf("organization %s: %w", id, err)
		}
		if len(snap.Entries) == 0 && len(snap.Exclusions) == 0 && len(snap.Templates) == 0 {
			continue
		}
		exp.Tenants = append(exp.Tenants, snap)
	}
	return exp, nil
}
