package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// runIssueLinks derives same-issue links of stored findings, per tenant.
func runIssueLinks(ctx context.Context, db *sql.DB, tenantFlag string, apply, asJSON bool, batch int) int {
	repo := postgres.NewFindingIssueLinkRepository(&postgres.DB{DB: db})
	var tenants []shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else {
		var err error
		if tenants, err = repo.TenantsWithLinkableFindings(ctx); err != nil {
			fail(2, err.Error())
		}
	}
	code := 0
	reports := make([]*postgres.IssueLinkBackfill, 0, len(tenants))
	for _, t := range tenants {
		rep, err := repo.BackfillLinks(ctx, t, apply, batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "links: tenant %s: %v\n", t, err)
			code = 1
			continue
		}
		reports = append(reports, rep)
		if !asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): findings %d, keys %d; link %d, release %d, keys too common %d\n",
				rep.TenantID, mode, rep.Findings, rep.Keys, rep.Linked, rep.Released, rep.Crowded)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}
