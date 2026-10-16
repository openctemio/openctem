package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// remediationKeysReport is one tenant's result of -remediation-keys.
type remediationKeysReport struct {
	TenantID string                  `json:"tenant_id"`
	Applied  bool                    `json:"applied"`
	Changes  *remediation.KeyChanges `json:"changes"`
}

// runRemediationKeys re-derives the remediation group key of every finding
// of one tenant or of every tenant with findings. A dry run (the default)
// only reads and prints what would change, per key kind.
func runRemediationKeys(ctx context.Context, db *sql.DB, tenantFlag string, apply, asJSON bool, batch int) int {
	applier := remediation.NewKeyApplier(postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: db}), logger.NewNop())
	applier.SetAuditWriter(postgres.NewAuditRepository(&postgres.DB{DB: db}))
	var tenants []shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		tenants = []shared.ID{id}
	} else {
		var err error
		if tenants, err = applier.Tenants(ctx); err != nil {
			fail(2, err.Error())
		}
	}
	code := 0
	reports := make([]remediationKeysReport, 0, len(tenants))
	for _, t := range tenants {
		ch, err := applier.Backfill(ctx, t, apply, batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "remediation keys: tenant %s: %v\n", t, err)
			code = 1
		}
		if ch == nil {
			continue
		}
		reports = append(reports, remediationKeysReport{TenantID: t.String(), Applied: apply, Changes: ch})
		if !asJSON {
			mode := modeDryRun
			if apply {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): scanned %d, added %d, changed %d, removed %d, unchanged %d, failed %d; keys before %s; after %s\n",
				t, mode, ch.Scanned, ch.Added, ch.Changed, ch.Removed, ch.Unchanged, ch.Failed, kinds(ch.Before), kinds(ch.After))
			for _, c := range ch.Campaigns {
				switch c.Action {
				case remediation.CampaignAmbiguous:
					fmt.Printf("  WARNING campaign %s %q tracks %s: its %d findings split over several keys, lost their key, or share the new key with other findings; re-create it from the new groups\n",
						c.CampaignID, c.Name, c.OldKey, c.Findings)
				case remediation.CampaignStale:
					fmt.Printf("  WARNING campaign %s %q tracks %s, which no finding has\n", c.CampaignID, c.Name, c.OldKey)
				default:
					fmt.Printf("  campaign %s %q %s: %s -> %s (%d findings)\n", c.CampaignID, c.Name, c.Action, c.OldKey, c.NewKey, c.Findings)
				}
			}
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}

// kinds renders per-kind counts as "rotate=2 upgrade=5" (or "none").
func kinds(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}
