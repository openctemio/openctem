package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// runVulnAliases re-keys stored findings onto the CVE the feed aliases their
// advisory id to, per tenant; an applying run writes one audit entry per
// tenant it changed.
func runVulnAliases(ctx context.Context, db *sql.DB, tenantFlag string, apply, asJSON bool, batch int) int {
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewFindingIssueLinkRepository(pdb)
	resolver := postgres.NewCVECorpusRepository(pdb)
	var tenants []shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else {
		var err error
		if tenants, err = aliasTenants(ctx, db); err != nil {
			fail(2, err.Error())
		}
	}
	code := 0
	runID := toolaudit.NewRunID()
	var w toolaudit.Writer = postgres.NewAuditRepository(pdb)
	reports := make([]*postgres.AliasRekeyReport, 0, len(tenants))
	for _, t := range tenants {
		rep, err := repo.RekeyVulnAliases(ctx, t, resolver, apply, batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vuln-aliases: tenant %s: %v\n", t, err)
			code = 1
			continue
		}
		reports = append(reports, rep)
		if apply && (rep.Rekeyed > 0 || rep.Linked > 0) {
			if err := toolaudit.Record(ctx, w, toolaudit.Event{
				TenantID: t, Action: audit.ActionFindingsRefingerprinted, ResourceType: audit.ResourceTypeFinding,
				Actor: "refingerprint", RunID: runID,
				Counts: map[string]int{"scanned": rep.Scanned, "rekeyed": rep.Rekeyed, "linked": rep.Linked},
			}); err != nil {
				fmt.Fprintf(os.Stderr, "vuln-aliases: tenant %s: %v\n", t, err)
				code = 1
			}
		}
		if !asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): scanned %d, re-keyed %d, linked %d, skipped %d\n",
				rep.TenantID, mode, rep.Scanned, rep.Rekeyed, rep.Linked, rep.Skipped)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}

// aliasTenants lists the tenants with findings an alias can re-key.
func aliasTenants(ctx context.Context, db *sql.DB) ([]shared.ID, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM findings
		WHERE identity_key IS NOT NULL AND identity_key->>'kind' IN ('sca', 'network', 'dast') AND status <> 'duplicate'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}
