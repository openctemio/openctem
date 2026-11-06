package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// keyBatch is how many findings one remediation-key re-derivation reads.
const keyBatch = 500

// runResetMaskSecretFingerprints clears the mask-derived secret fingerprints
// and "RE…ED" previews of every tenant (or one), then re-derives the
// remediation keys of the findings it changed. A dry run prints counts only.
// before is the time the rotation-group fix was deployed.
func runResetMaskSecretFingerprints(ctx context.Context, db *sql.DB, tenantFlag, before string, apply, asJSON bool, batch int) int {
	if before == "" {
		fail(2, "-before is required with -reset-mask-secret-fingerprints: the RFC 3339 time the rotation-group fix was deployed (later fingerprints come from the raw secret and are kept)")
	}
	cutoff, err := time.Parse(time.RFC3339, before)
	if err != nil {
		fail(2, "-before: not an RFC 3339 time")
	}
	var only *shared.ID
	if tenantFlag != "" {
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		only = &id
	}
	tenants, err := postgres.MaskSecretResetTenants(ctx, db, only, cutoff)
	if err != nil {
		fail(2, err.Error())
	}
	applier := remediation.NewKeyApplier(postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: db}), logger.NewNop())
	var auditWriter toolaudit.Writer = postgres.NewAuditRepository(&postgres.DB{DB: db})
	runID := toolaudit.NewRunID()
	code := 0
	reports := make([]*postgres.SecretMaskResetReport, 0, len(tenants))
	for _, t := range tenants {
		rep, err := postgres.ResetMaskSecretFingerprints(ctx, db, t, cutoff, apply, batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reset mask secret fingerprints: tenant %s: %v\n", t, err)
			code = 1
			if rep == nil {
				continue
			}
		}
		if apply && len(rep.FindingIDs) > 0 {
			for i := 0; i < len(rep.FindingIDs); i += keyBatch {
				end := min(i+keyBatch, len(rep.FindingIDs))
				if _, err := applier.ApplyIDs(ctx, t, rep.FindingIDs[i:end], true); err != nil {
					fmt.Fprintf(os.Stderr, "reset mask secret fingerprints: tenant %s: remediation keys: %v\n", t, err)
					code = 1
				}
			}
			if err := toolaudit.Record(ctx, auditWriter, toolaudit.Event{
				TenantID: t, Action: audit.ActionFindingsRefingerprinted, ResourceType: audit.ResourceTypeFinding,
				Actor: "refingerprint", RunID: runID,
				Counts: map[string]int{"secret_fingerprints_cleared": rep.Fingerprints, "secret_previews_cleared": rep.Previews},
			}); err != nil {
				fmt.Fprintf(os.Stderr, "reset mask secret fingerprints: tenant %s: %v\n", t, err)
				code = 1
			}
		}
		reports = append(reports, rep)
		if !asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): secret fingerprints %d, previews %d, grouped rotation tasks to review %d, still held %d\n",
				rep.TenantID, mode, rep.Fingerprints, rep.Previews, rep.GroupedRotationTasks, rep.Remaining)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}
