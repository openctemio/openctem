package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// emailScrubTenants resolves the tenants of -mask-emails: the -tenant list
// (comma-separated ids) or, with -all-tenants, every tenant. Exactly one of
// the two is required, so a typo never widens a run to every tenant.
func emailScrubTenants(ctx context.Context, db *sql.DB, tenantFlag string, all bool) ([]shared.ID, error) {
	if (tenantFlag == "") == !all {
		return nil, fmt.Errorf("-mask-emails needs -tenant <id>[,<id>...] or -all-tenants (one of them)")
	}
	if all {
		return postgres.EmailScrubTenants(ctx, db)
	}
	parts := strings.Split(tenantFlag, ",")
	seen := make(map[shared.ID]bool, len(parts))
	out := make([]shared.ID, 0, len(parts))
	for _, s := range parts {
		id, err := shared.IDFromString(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("-tenant: not an id")
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// emailScrubActor names the command in the audit entry (it has no user).
const emailScrubActor = "refingerprint"

// AuditEmailScrub records an applied run that masked a tenant's rows in that
// tenant's audit log: one entry, counts only.
func AuditEmailScrub(ctx context.Context, w toolaudit.Writer, runID string, rep *postgres.EmailScrubReport) error {
	if rep == nil || !rep.Applied || rep.FindingsMasked+rep.EvidenceMasked == 0 {
		return nil
	}
	tid, err := shared.IDFromString(rep.TenantID)
	if err != nil {
		return err
	}
	return toolaudit.Record(ctx, w, toolaudit.Event{
		TenantID: tid, Action: audit.ActionFindingsEmailsMasked, ResourceType: audit.ResourceTypeFinding,
		Actor: emailScrubActor, RunID: runID,
		Counts: map[string]int{
			"findings_masked": rep.FindingsMasked, "evidence_masked": rep.EvidenceMasked,
			"human_findings_left": rep.HumanFindingsLeft, "evidence_unreadable": rep.EvidenceUnreadable,
			"remaining": rep.Remaining,
		},
	})
}

// runMaskEmails masks the e-mail addresses left in stored findings and
// evidence, tenant by tenant (postgres.ScrubStoredEmails). Output is counts
// only, never a value.
func runMaskEmails(ctx context.Context, db *sql.DB, tenantFlag string, all, apply, asJSON bool, batch int) int {
	tenants, err := emailScrubTenants(ctx, db, tenantFlag, all)
	if err != nil {
		fail(2, err.Error())
	}
	var auditWriter toolaudit.Writer = postgres.NewAuditRepository(&postgres.DB{DB: db})
	runID := toolaudit.NewRunID()
	code := 0
	reports := make([]*postgres.EmailScrubReport, 0, len(tenants))
	for _, t := range tenants {
		rep, err := postgres.ScrubStoredEmails(ctx, db, t, apply, batch)
		if err != nil {
			// The batches committed before the error stay; a rerun continues.
			fmt.Fprintf(os.Stderr, "mask emails: tenant %s: %v\n", t, err)
			code = 1
		}
		if rep == nil {
			continue
		}
		if err := AuditEmailScrub(ctx, auditWriter, runID, rep); err != nil {
			fmt.Fprintf(os.Stderr, "mask emails: tenant %s: %v\n", t, err)
			code = 1
		}
		reports = append(reports, rep)
		if !asJSON {
			mode := modeDryRun
			if rep.Applied {
				mode = modeApplied
			}
			fmt.Printf("tenant %s (%s): findings %d of %d read%s, human-reported left %d; evidence %d of %d read, unreadable %d; skipped (locked) %d\n",
				rep.TenantID, mode, rep.FindingsMasked, rep.FindingsRead, formatColumns(rep.Columns), rep.HumanFindingsLeft,
				rep.EvidenceMasked, rep.EvidenceRead, rep.EvidenceUnreadable, rep.Remaining)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"applied": apply, "tenants": reports})
	}
	return code
}

// formatColumns prints the per-column counts in name order.
func formatColumns(cols map[string]int) string {
	if len(cols) == 0 {
		return ""
	}
	names := make([]string, 0, len(cols))
	for n := range cols {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s %d", n, cols[n]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
