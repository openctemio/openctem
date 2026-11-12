package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/tools/toolaudit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/exposure"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// The audit entry's actor and the count of findings a run read.
const (
	auditActor   = "refingerprint"
	countScanned = "scanned"
)

// InfoExposureReport is what -info-exposures did (or would do) in one tenant.
type InfoExposureReport struct {
	TenantID string `json:"tenant_id"`
	Applied  bool   `json:"applied"`
	// Skipped: the organization files info matches as findings (its EASM
	// setting); nothing of it is touched.
	Skipped bool `json:"skipped_setting"`
	// Scanned open informational findings of template scanners.
	Scanned int `json:"scanned"`
	// Moved (or would move) to exposures.
	Moved int `json:"moved"`
	// Held: worked on by a person or an integration (ticket, task, pending
	// approval or closure proposal); left as they are.
	Held int `json:"held"`
	// Invalid: no exposure could be built (logged); left as they are.
	Invalid int `json:"invalid"`
	// Restored by -down.
	Restore *postgres.ReclassifiedRestore `json:"restore,omitempty"`
}

// templateScanners are the tools whose info matches ingest files as
// exposures (internal/app/ingest/info_matches.go, templateScanner).
func templateScanners() []string {
	var out []string
	for _, k := range []stage.Key{stage.VulnTemplates, stage.DASTWeb} {
		st, ok := stage.Lookup(k)
		if !ok {
			continue
		}
		for _, i := range st.Implementations {
			if !slices.Contains(out, i.Tool) {
				out = append(out, i.Tool)
			}
		}
	}
	return out
}

// InfoMatchEvent is the exposure event ingest files for the stored finding
// f (the same template match, so the same fingerprint).
func InfoMatchEvent(tenantID shared.ID, f postgres.InfoFinding) (*exposure.ExposureEvent, error) {
	return exposure.NewTemplateMatchEvent(tenantID, exposure.TemplateMatch{
		AssetID: f.AssetID, Tool: f.Tool, RuleID: f.RuleID, Title: f.Title, Matcher: f.Matcher,
		URL: f.URL, Tags: f.Tags,
	})
}

// tenantSettings reads whether an organization files info matches as
// findings.
type tenantSettings interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// ReclassifyInfoTenant moves (apply) or counts (dry run) the tenant's open
// informational template-scan findings, in batches of batch. A tenant that
// files info matches as findings is skipped. Idempotent: a moved finding is
// no longer open, and the exposure upsert is keyed on its fingerprint.
func ReclassifyInfoTenant(ctx context.Context, repo *postgres.InfoReclassifyRepository, tenants tenantSettings,
	tenantID shared.ID, apply bool, batch int,
) (*InfoExposureReport, error) {
	rep := &InfoExposureReport{TenantID: tenantID.String(), Applied: apply}
	t, err := tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read tenant: %w", err)
	}
	if t.TypedSettings().EASM.InfoMatchesAsFindings {
		rep.Skipped = true
		return rep, nil
	}
	tools := templateScanners()
	after := ""
	for {
		page, err := repo.InfoFindings(ctx, tenantID, tools, after, batch)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return rep, nil
		}
		after = page[len(page)-1].ID.String()
		moves := make([]postgres.InfoReclassification, 0, len(page))
		for _, f := range page {
			rep.Scanned++
			if f.Held {
				rep.Held++
				continue
			}
			ev, err := InfoMatchEvent(tenantID, f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "info-exposures: tenant %s finding %s: %v\n", tenantID, f.ID, err)
				rep.Invalid++
				continue
			}
			moves = append(moves, postgres.InfoReclassification{Finding: f, Event: ev})
		}
		if !apply {
			rep.Moved += len(moves)
			continue
		}
		moved, err := repo.Reclassify(ctx, tenantID, moves)
		if err != nil {
			return nil, err
		}
		rep.Moved += len(moved)
	}
}

// runInfoExposures is -info-exposures: every tenant with an open
// informational template-scan finding (or -tenant), dry run unless -apply;
// -down -apply undoes the moves. An applying run writes one audit entry
// per tenant it changed.
func runInfoExposures(ctx context.Context, db *sql.DB, tenantFlag string, apply, down, asJSON bool, batch int) int {
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewInfoReclassifyRepository(pdb)
	tenants := postgres.NewTenantRepository(pdb)
	var ids []shared.ID
	switch {
	case tenantFlag != "":
		id, err := shared.IDFromString(tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		ids = []shared.ID{id}
	case down:
		var err error
		if ids, err = reclassifiedTenants(ctx, db); err != nil {
			fail(2, err.Error())
		}
	default:
		var err error
		if ids, err = repo.TenantsWithInfoFindings(ctx, templateScanners()); err != nil {
			fail(2, err.Error())
		}
	}
	code := 0
	runID := toolaudit.NewRunID()
	var w toolaudit.Writer = postgres.NewAuditRepository(pdb)
	reports := make([]*InfoExposureReport, 0, len(ids))
	for _, t := range ids {
		rep, err := infoExposuresTenant(ctx, repo, tenants, t, apply, down, batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "info-exposures: tenant %s: %v\n", t, err)
			code = 1
			continue
		}
		reports = append(reports, rep)
		changed := rep.Moved
		if rep.Restore != nil {
			changed = rep.Restore.Reopened
		}
		if apply && changed > 0 {
			counts := map[string]int{countScanned: rep.Scanned, "moved": rep.Moved, "held": rep.Held, "invalid": rep.Invalid}
			if rep.Restore != nil {
				counts = map[string]int{"reopened": rep.Restore.Reopened, "events_removed": rep.Restore.EventsRemoved,
					"events_kept": rep.Restore.EventsKept}
			}
			if err := toolaudit.Record(ctx, w, toolaudit.Event{
				TenantID: t, Action: audit.ActionFindingsReclassified, ResourceType: audit.ResourceTypeFinding,
				Actor: auditActor, RunID: runID, Counts: counts,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "info-exposures: tenant %s: %v\n", t, err)
				code = 1
			}
		}
		if !asJSON {
			printInfoExposureReport(rep)
		}
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	return code
}

func infoExposuresTenant(ctx context.Context, repo *postgres.InfoReclassifyRepository, tenants tenantSettings,
	t shared.ID, apply, down bool, batch int,
) (*InfoExposureReport, error) {
	if !down {
		return ReclassifyInfoTenant(ctx, repo, tenants, t, apply, batch)
	}
	rep := &InfoExposureReport{TenantID: t.String(), Applied: apply, Restore: &postgres.ReclassifiedRestore{}}
	if !apply {
		n, err := repo.CountReclassified(ctx, t)
		if err != nil {
			return nil, err
		}
		rep.Restore.Reopened = n
		return rep, nil
	}
	for {
		r, err := repo.RestoreReclassified(ctx, t, batch)
		if err != nil {
			return nil, err
		}
		rep.Restore.Reopened += r.Reopened
		rep.Restore.EventsRemoved += r.EventsRemoved
		rep.Restore.EventsKept += r.EventsKept
		if r.Reopened == 0 {
			return rep, nil
		}
	}
}

func printInfoExposureReport(rep *InfoExposureReport) {
	mode := modeDryRun
	if rep.Applied {
		mode = modeApplied
	}
	switch {
	case rep.Skipped:
		fmt.Printf("tenant %s (%s): skipped, the organization files info matches as findings\n", rep.TenantID, mode)
	case rep.Restore != nil:
		fmt.Printf("tenant %s (%s): reopened %d, exposure events removed %d, kept %d\n",
			rep.TenantID, mode, rep.Restore.Reopened, rep.Restore.EventsRemoved, rep.Restore.EventsKept)
	default:
		fmt.Printf("tenant %s (%s): scanned %d, moved to exposures %d, held %d, invalid %d\n",
			rep.TenantID, mode, rep.Scanned, rep.Moved, rep.Held, rep.Invalid)
	}
}

// reclassifiedTenants lists the tenants with findings -info-exposures moved.
func reclassifiedTenants(ctx context.Context, db *sql.DB) ([]shared.ID, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT tenant_id::text FROM findings
		WHERE status = 'resolved' AND closure_reason = 'reclassified_exposure' ORDER BY 1`)
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
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
