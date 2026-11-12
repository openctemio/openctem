package postgres

// What a scan file proves closes (docs/architecture/finding-import.md, "What
// a Nessus import closes"). The candidates of a host are the open findings
// of the file's tool on the host's asset that the upload did not report,
// under the guards of a full-coverage upload (importCoverageScope,
// importCloseableSQL). The application decides per finding, from the file's
// own coverage, which may close; every write re-checks the guards and that
// the finding was not seen after the file's observation. Every statement is
// scoped by tenant_id.

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// The timeline actor of a scan file's closes.
const (
	fileCloseActivity  = "auto_resolved"
	fileCloseSource    = "auto"
	fileCloseActorType = "scanner"
	fileCloseActorName = "system: scan file import"
)

// FileCoverageCandidates returns the open findings of tool on assets that
// the upload (receiptID) did not report, with what deciding a close needs,
// and how many open findings the scope has (the blinding guard). The
// receipt must be complete (AbsenceReceiptByID).
func (r *FindingRepository) FileCoverageCandidates(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string,
	receiptID shared.ID) ([]vulnerability.FileCoverageCandidate, int, error) {
	if len(assets) == 0 || tool == "" {
		return nil, 0, nil
	}
	if _, err := r.AbsenceReceiptByID(ctx, tenantID, receiptID); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, f.asset_id::text,
			COALESCE(NULLIF(f.native_vuln_id, ''), f.rule_id, ''),
			COALESCE(f.source_meta->'native'->>'family', ''),
			COALESCE(f.source_extra->>'plugin_type', ''),
			COALESCE(f.finding_type, '') = 'compliance',
			COALESCE(f.last_seen_at, f.created_at),
			NOT `+secretFindingSQL("f")+` AND `+importCloseableSQL+`,
			`+importNotReportedSQL+`
		FROM findings f
		WHERE `+importCoverageScope,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, receiptID.String())
	if err != nil {
		return nil, 0, fmt.Errorf("file coverage candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []vulnerability.FileCoverageCandidate
	open := 0
	for rows.Next() {
		var id, asset string
		var c vulnerability.FileCoverageCandidate
		var notReported bool
		if err := rows.Scan(&id, &asset, &c.PluginID, &c.Family, &c.PluginType, &c.Compliance, &c.LastSeenAt,
			&c.Closeable, &notReported); err != nil {
			return nil, 0, fmt.Errorf("scan file coverage candidate: %w", err)
		}
		open++
		if !notReported {
			continue
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		aid, err := shared.IDFromString(asset)
		if err != nil {
			continue
		}
		c.ID, c.AssetID = fid, aid
		out = append(out, c)
	}
	return out, open, rows.Err()
}

// ResolveFileCoverage closes findings a scan file proved gone, each at the
// time the file observed its host (never later than now). The UPDATE
// re-checks the scope, the guards, that the upload did not report it and
// that it was not seen after that time.
func (r *FindingRepository) ResolveFileCoverage(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string,
	receiptID shared.ID, closes []vulnerability.TimedClose) ([]shared.ID, error) {
	if len(closes) == 0 {
		return nil, nil
	}
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	ids, ats := timedArgs(closes)
	return r.db.queryIDsWithTransition(ctx, findingTransition{ActivityType: fileCloseActivity, Source: fileCloseSource,
		Reason: "not_in_scan_file", ActorType: fileCloseActorType, ActorName: fileCloseActorName,
		Message: "A scan file whose host and check coverage is complete no longer reported it"}, `
		UPDATE findings f
		SET status = 'resolved', resolution = 'auto_fixed', closure_reason = 'fixed', verification = 'covered_scan',
			resolved_at = LEAST(i.observed, NOW()), updated_at = NOW()
		FROM unnest($5::uuid[], $6::timestamptz[]) AS i(id, observed)
		WHERE f.id = i.id
			AND `+importCoverageScope+`
			AND `+importNotReportedSQL+`
			AND NOT `+secretFindingSQL("f")+`
			AND `+importCloseableSQL+`
			AND COALESCE(f.last_seen_at, f.created_at) <= i.observed
		RETURNING f.id::text`,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, receiptID.String(), pq.Array(ids), pq.Array(ats))
}

// compliancePassScope is the WHERE clause of the open failures a passed
// compliance result may resolve ($1 tenant, $2 assets, $3 tool): the same
// check (fingerprint) on an asset of the uploader's scope.
var compliancePassScope = `
	f.tenant_id = $1
	AND f.asset_id = ANY($2::uuid[])
	AND COALESCE(f.last_seen_tool, f.tool_name) = $3
	AND f.finding_type = 'compliance'
	AND f.branch_id IS NULL
	AND f.status IN ` + autoResolveFromSQL + `
	AND f.source NOT IN ` + coverageProtectedSources

// CompliancePassCandidates returns the open compliance findings of tool on
// assets whose fingerprint is one of fingerprints.
func (r *FindingRepository) CompliancePassCandidates(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string,
	fingerprints []string) ([]vulnerability.FileCoverageCandidate, error) {
	if len(assets) == 0 || len(fingerprints) == 0 || tool == "" {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, f.asset_id::text, f.fingerprint, COALESCE(f.last_seen_at, f.created_at),
			NOT `+secretFindingSQL("f")+` AND `+importCloseableSQL+`
		FROM findings f
		WHERE `+compliancePassScope+` AND f.fingerprint = ANY($4::text[])`,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("compliance pass candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []vulnerability.FileCoverageCandidate
	for rows.Next() {
		var id, asset string
		c := vulnerability.FileCoverageCandidate{Compliance: true}
		if err := rows.Scan(&id, &asset, &c.Fingerprint, &c.LastSeenAt, &c.Closeable); err != nil {
			return nil, fmt.Errorf("scan compliance pass candidate: %w", err)
		}
		fid, err1 := shared.IDFromString(id)
		aid, err2 := shared.IDFromString(asset)
		if err1 != nil || err2 != nil {
			continue
		}
		c.ID, c.AssetID = fid, aid
		out = append(out, c)
	}
	return out, rows.Err()
}

// ResolveCompliancePassed resolves open compliance failures whose check a
// scan file reported as passed, each at the time the check ran; the UPDATE
// re-checks the scope, the guards and that the failure was not seen later.
func (r *FindingRepository) ResolveCompliancePassed(ctx context.Context, tenantID shared.ID, assets []shared.ID, tool string,
	closes []vulnerability.TimedClose) ([]shared.ID, error) {
	if len(closes) == 0 {
		return nil, nil
	}
	if autoResolvePaused(ctx, r.db, tenantID.String()) {
		return nil, nil
	}
	ids, ats := timedArgs(closes)
	return r.db.queryIDsWithTransition(ctx, findingTransition{ActivityType: fileCloseActivity, Source: fileCloseSource,
		Reason: "compliance_check_passed", ActorType: fileCloseActorType, ActorName: fileCloseActorName,
		Message: "A scan file reported this compliance check as passed"}, `
		UPDATE findings f
		SET status = 'resolved', resolution = 'auto_fixed', closure_reason = 'fixed', verification = 'covered_scan',
			resolved_at = LEAST(i.observed, NOW()), updated_at = NOW()
		FROM unnest($4::uuid[], $5::timestamptz[]) AS i(id, observed)
		WHERE f.id = i.id
			AND `+compliancePassScope+`
			AND NOT `+secretFindingSQL("f")+`
			AND `+importCloseableSQL+`
			AND COALESCE(f.last_seen_at, f.created_at) <= i.observed
		RETURNING f.id::text`,
		tenantID.String(), pq.Array(importScopeIDs(assets)), tool, pq.Array(ids), pq.Array(ats))
}

// timedArgs are the ids and their times (RFC 3339, cast to timestamptz).
func timedArgs(closes []vulnerability.TimedClose) (ids, ats []string) {
	ids = make([]string, len(closes))
	ats = make([]string, len(closes))
	for i, c := range closes {
		ids[i], ats[i] = c.ID.String(), c.At.UTC().Format(time.RFC3339Nano)
	}
	return ids, ats
}
