package postgres

// One-time fold of version-match findings stored per service before
// locations existed (docs/architecture/vulnerability-matching.md,
// "Locations"; cmd/vulnmatch-locations).
//
// The matcher used to key a finding on (asset, CVE, port), and each web
// origin of a host is its own service asset, so one web server answering on
// http:80 and https:443 had two findings. Findings of one tenant with the
// same host, product, version and CVE are one finding now: the oldest
// survives (taking the strongest open status of the group), with its history, comments, tickets and SLA deadline;
// each other one becomes a location of it (with the state its status says)
// and a tombstone (status duplicate, duplicate_of) whose comments, timeline,
// tickets, evidence and other references move to the survivor. Nothing is
// deleted. Every fold is audited and journaled (finding_location_merges) so
// RevertLocationMerges can put it back.
//
// The fold is conservative: a group is skipped (and reported) when a person
// decided something on one of its findings that the fold would override
// (accepted, a person's false positive or fix, review states), when the
// services are seen differently by some user (scope rows, private program
// links), when the findings have different assignees, or when a loser has a
// pending status request or retest. The loser's former keys are not made
// aliases of the survivor: a scanner report on another service keeps
// landing on that service's own asset, so no data scope changes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// LocationMergeRepository folds and restores per-service version-match
// duplicates. Every statement is scoped to one tenant.
type LocationMergeRepository struct{ db *DB }

// NewLocationMergeRepository creates a LocationMergeRepository.
func NewLocationMergeRepository(db *DB) *LocationMergeRepository {
	return &LocationMergeRepository{db: db}
}

// Skip reasons of a group.
const (
	MergeSkipPersonDecision  = "person_decision"
	MergeSkipInconsistent    = "inconsistent_states"
	MergeSkipScopeDiffers    = "scope_differs"
	MergeSkipAssigneeDiffers = "assignee_differs"
	MergeSkipPendingRequest  = "pending_request"
	MergeSkipChanged         = "changed_since_read"
)

// LocationMergeMember is one finding of a group.
type LocationMergeMember struct {
	FindingID string `json:"finding_id"`
	Status    string `json:"status"`
	// Location is the state its service gets on the survivor.
	Location string `json:"location_state"`
	Service  string `json:"service"`
}

// LocationMergeGroup is one host, product, version and CVE with more than
// one finding.
type LocationMergeGroup struct {
	Survivor LocationMergeMember   `json:"survivor"`
	Losers   []LocationMergeMember `json:"losers"`
	// Reopen: the survivor was closed as fixed by the matcher while another
	// service is still affected; it reopens (as the matcher would).
	Reopen bool `json:"reopen,omitempty"`
	// RaiseTo is the strongest open triage status (new, confirmed, in
	// progress or fix applied) among the affected rows of the group, set
	// only when it outranks the status the survivor ends with.
	RaiseTo string `json:"raise_to,omitempty"`
	// Skipped names why the group is left alone; empty when it merges.
	Skipped string `json:"skipped,omitempty"`
	// Notes are facts a reviewer may want (a loser with a stronger open
	// status, an earlier SLA deadline the survivor takes).
	Notes []string `json:"notes,omitempty"`
}

// LocationMergeReport is what one tenant's run did, or would do.
type LocationMergeReport struct {
	TenantID string               `json:"tenant_id"`
	RunID    string               `json:"run_id,omitempty"`
	Applied  bool                 `json:"applied"`
	Scanned  int                  `json:"scanned"`
	Groups   []LocationMergeGroup `json:"groups"`
	Merged   int                  `json:"merged"`
	Skipped  int                  `json:"skipped"`
}

type mergeCandidate struct {
	id, assetID, assetName, status, closure, verification, resolution string
	cve, productID, versionID, version, linkLocation, evidence        string
	fingerprint, assignee, transport                                  string
	port                                                              int
	created                                                           time.Time
	sla                                                               sql.NullTime
}

// locationStateOf is the location state a finding's status stands for, or
// "" when a person's decision would be lost by folding it.
func locationStateOf(c mergeCandidate) softwarematch.LocationState {
	switch vulnerability.FindingStatus(c.status) {
	case vulnerability.FindingStatusNew, vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied:
		return softwarematch.LocationAffected
	case vulnerability.FindingStatusResolved:
		if c.closure == string(vulnerability.ClosureReasonFixed) && c.verification == string(vulnerability.VerificationSourceReported) {
			return softwarematch.LocationFixed
		}
	case vulnerability.FindingStatusFalsePositive:
		if c.resolution == "advisory_updated" && c.verification == string(vulnerability.VerificationSourceReported) {
			return softwarematch.LocationNotAffected
		}
	}
	return ""
}

// PlanLocationMerges groups the tenant's version-match findings on service
// assets by host, product, version and CVE and, with apply, folds every
// group that is safe to fold. runID names the run in the journal and audit.
func (r *LocationMergeRepository) PlanLocationMerges(ctx context.Context, tenantID shared.ID, apply bool, runID string) (*LocationMergeReport, error) {
	tenant := tenantID.String()
	rep := &LocationMergeReport{TenantID: tenant, Applied: apply, Groups: []LocationMergeGroup{}}
	if apply {
		rep.RunID = runID
	}
	cands, err := r.listCandidates(ctx, r.db, tenant, nil)
	if err != nil {
		return nil, err
	}
	rep.Scanned = len(cands)
	groups := groupCandidates(cands)
	if len(groups) == 0 {
		return rep, nil
	}
	var assetIDs []shared.ID
	for _, g := range groups {
		for _, c := range g {
			assetIDs = append(assetIDs, shared.MustIDFromString(c.assetID))
		}
	}
	sigs, err := scopeSignatures(ctx, r.db, tenant, assetIDs)
	if err != nil {
		return nil, err
	}
	pending, err := r.pendingRequests(ctx, tenant, groups)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		plan := planGroup(g, sigs, pending)
		if plan.Skipped == "" && apply {
			if err := r.applyGroup(ctx, tenant, runID, g, &plan); err != nil {
				return nil, err
			}
		}
		if plan.Skipped != "" {
			rep.Skipped++
		} else {
			rep.Merged += len(plan.Losers)
		}
		rep.Groups = append(rep.Groups, plan)
	}
	return rep, nil
}

const mergeCandidateSQL = `
	SELECT f.id::text, f.asset_id::text, a.name, f.status, COALESCE(f.closure_reason, ''), COALESCE(f.verification, ''),
	       COALESCE(f.resolution, ''), upper(COALESCE(f.cve_id, '')),
	       COALESCE(f.metadata->'version_match'->>'product_id', ''), COALESCE(f.metadata->'version_match'->>'version_id', ''),
	       COALESCE(f.metadata->'version_match'->>'version', ''), COALESCE(f.metadata->'version_match'->>'location', ''),
	       COALESCE(f.metadata->'version_match'->>'evidence', ''),
	       f.fingerprint, COALESCE(f.assigned_to::text, ''), COALESCE(f.network_transport, ''), COALESCE(f.network_port, 0),
	       f.created_at, f.sla_deadline
	FROM findings f
	JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
	WHERE f.tenant_id = $1 AND ` + matcherOwnedSQL + `
	  AND f.status <> 'duplicate'
	  AND a.asset_type = 'service'
	  AND NOT (COALESCE(f.metadata->'version_match', '{}'::jsonb) ? 'purl')
	  AND COALESCE(f.cve_id, '') <> ''`

func (r *LocationMergeRepository) listCandidates(ctx context.Context, q locationQueryer, tenant string, ids []string) ([]mergeCandidate, error) {
	query, args := mergeCandidateSQL+` ORDER BY f.created_at, f.id`, []any{tenant}
	if ids != nil {
		query = mergeCandidateSQL + ` AND f.id = ANY($2::uuid[]) ORDER BY f.created_at, f.id FOR UPDATE OF f`
		args = append(args, pq.Array(ids))
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list version-match findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []mergeCandidate
	for rows.Next() {
		var c mergeCandidate
		if err := rows.Scan(&c.id, &c.assetID, &c.assetName, &c.status, &c.closure, &c.verification, &c.resolution, &c.cve,
			&c.productID, &c.versionID, &c.version, &c.linkLocation, &c.evidence, &c.fingerprint, &c.assignee, &c.transport,
			&c.port, &c.created, &c.sla); err != nil {
			return nil, fmt.Errorf("scan version-match finding: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// groupCandidates groups by host, product, version and CVE, oldest first;
// only groups of two or more are returned, in a stable order.
func groupCandidates(cands []mergeCandidate) [][]mergeCandidate {
	byKey := map[string][]mergeCandidate{}
	for _, c := range cands {
		host := softwarematch.ServiceHost(c.assetName)
		if host == "" || c.productID == "" || c.versionID == "" {
			continue
		}
		k := host + "|" + c.productID + "|" + c.versionID + "|" + c.cve
		byKey[k] = append(byKey[k], c)
	}
	keys := make([]string, 0, len(byKey))
	for k, g := range byKey {
		if len(g) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([][]mergeCandidate, 0, len(keys))
	for _, k := range keys {
		g := byKey[k]
		sort.SliceStable(g, func(a, b int) bool {
			if !g[a].created.Equal(g[b].created) {
				return g[a].created.Before(g[b].created)
			}
			return g[a].id < g[b].id
		})
		out = append(out, g)
	}
	return out
}

func memberOf(c mergeCandidate) LocationMergeMember {
	return LocationMergeMember{FindingID: c.id, Status: c.status, Location: string(locationStateOf(c)),
		Service: softwarematch.LocationLabel(c.assetName, c.port, c.transport)}
}

// planGroup decides whether a group folds (see the file comment).
func planGroup(g []mergeCandidate, sigs map[shared.ID]string, pending map[string]bool) LocationMergeGroup {
	s := g[0]
	plan := LocationMergeGroup{Survivor: memberOf(s)}
	anyAffected := false
	for _, l := range g[1:] {
		plan.Losers = append(plan.Losers, memberOf(l))
	}
	for _, c := range g {
		st := locationStateOf(c)
		if st == "" {
			plan.Skipped = MergeSkipPersonDecision
			return plan
		}
		if st == softwarematch.LocationAffected {
			anyAffected = true
		}
	}
	for _, c := range g[1:] {
		if sigs[shared.MustIDFromString(c.assetID)] != sigs[shared.MustIDFromString(s.assetID)] ||
			sigs[shared.MustIDFromString(c.assetID)] == "" {
			plan.Skipped = MergeSkipScopeDiffers
			return plan
		}
		if c.assignee != "" && c.assignee != s.assignee {
			plan.Skipped = MergeSkipAssigneeDiffers
			return plan
		}
		if pending[c.id] {
			plan.Skipped = MergeSkipPendingRequest
			return plan
		}
		if findingStatusRank(c.status) > findingStatusRank(s.status) && locationStateOf(c) == softwarematch.LocationAffected &&
			locationStateOf(s) == softwarematch.LocationAffected {
			plan.Notes = append(plan.Notes, "loser "+c.id+" has the stronger open status "+c.status+"; the survivor takes it")
		}
		if c.sla.Valid && (!s.sla.Valid || c.sla.Time.Before(s.sla.Time)) && locationStateOf(c) == softwarematch.LocationAffected {
			plan.Notes = append(plan.Notes, "loser "+c.id+" has an earlier SLA deadline; the survivor takes it")
		}
	}
	// The survivor takes the strongest open triage status of the rows that
	// are still affected: a confirmed finding is not demoted to new by
	// folding into it. A reopened survivor starts at confirmed.
	end := s.status
	if locationStateOf(s) == softwarematch.LocationFixed && anyAffected {
		end = string(vulnerability.FindingStatusConfirmed)
	}
	best := findingStatusRank(end)
	for _, c := range g {
		if locationStateOf(c) != softwarematch.LocationAffected {
			continue
		}
		if r := findingStatusRank(c.status); r >= 2 && r <= 4 && r > best {
			best, plan.RaiseTo = r, c.status
		}
	}
	switch locationStateOf(s) {
	case softwarematch.LocationFixed:
		plan.Reopen = anyAffected
	case softwarematch.LocationNotAffected:
		if anyAffected {
			plan.Skipped = MergeSkipInconsistent
		}
	}
	return plan
}

// pendingRequests reports the losers with a pending status request or
// retest: moving them would make a request about one service apply to the
// merged finding.
func (r *LocationMergeRepository) pendingRequests(ctx context.Context, tenant string, groups [][]mergeCandidate) (map[string]bool, error) {
	var ids []string
	for _, g := range groups {
		for _, c := range g[1:] {
			ids = append(ids, c.id)
		}
	}
	out := map[string]bool{}
	rows, err := r.db.QueryContext(ctx, `
		SELECT finding_id::text FROM finding_status_approvals WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[]) AND status = 'pending'
		UNION
		SELECT finding_id::text FROM finding_retests WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[]) AND status = 'pending'`,
		tenant, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("pending requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// The finding columns a fold may change, journaled before and after.
const (
	survivorSnapshotSQL = `jsonb_build_object('status', status, 'resolution', resolution, 'closure_reason', closure_reason,
		'verification', verification, 'resolved_at', resolved_at, 'resolved_by', resolved_by, 'observation_state', observation_state,
		'work_item_uris', work_item_uris, 'tags', tags, 'first_detected_at', first_detected_at, 'last_seen_at', last_seen_at,
		'sla_deadline', sla_deadline, 'sla_status', sla_status, 'duplicate_count', duplicate_count)`
	loserSnapshotSQL = `jsonb_build_object('status', status, 'resolution', resolution, 'closure_reason', closure_reason,
		'verification', verification, 'resolved_at', resolved_at, 'resolved_by', resolved_by, 'fingerprint', fingerprint,
		'duplicate_of', duplicate_of)`
)

var survivorRestoreColumns = strings.Fields(`status resolution closure_reason verification resolved_at resolved_by
	observation_state work_item_uris tags first_detected_at last_seen_at sla_deadline sla_status duplicate_count`)

// Reasons of the location merge on the timeline, in the audit log and in
// the finding transition.
const (
	reasonLocationMerge         = "location_merge"
	reasonLocationMergeReverted = "location_merge_reverted"
	vulnmatchSource             = "vulnmatch"
)

var causeLocationMerge = findingTransition{
	Source: vulnmatchSource, Reason: reasonLocationMerge, ActorName: "system: version-match location merge",
	Message: "Folded into one finding per host, product, version and CVE",
}

// applyGroup folds one group in one transaction.
func (r *LocationMergeRepository) applyGroup(ctx context.Context, tenant, runID string, g []mergeCandidate, plan *LocationMergeGroup) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := setFindingTransition(ctx, tx, causeLocationMerge); err != nil {
			return err
		}
		ids := make([]string, len(g))
		for i, c := range g {
			ids[i] = c.id
		}
		// Lock and re-read: the group folds only as it was planned.
		now, err := r.listCandidates(ctx, tx, tenant, ids)
		if err != nil {
			return err
		}
		if !sameCandidates(g, now) {
			plan.Skipped = MergeSkipChanged
			return nil
		}
		survivor := g[0]
		var sBefore []byte
		if err := tx.QueryRowContext(ctx, `SELECT `+survivorSnapshotSQL+` FROM findings WHERE tenant_id = $1 AND id = $2`,
			tenant, survivor.id).Scan(&sBefore); err != nil {
			return fmt.Errorf("snapshot survivor: %w", err)
		}
		if plan.Reopen {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'confirmed', resolution = NULL, resolved_at = NULL,
					observation_state = 'present', updated_at = NOW()
				WHERE tenant_id = $1 AND id = $2 AND status = 'resolved'`, tenant, survivor.id); err != nil {
				return fmt.Errorf("reopen survivor: %w", err)
			}
		}
		if plan.RaiseTo != "" {
			// The survivor's pre-merge status is journaled (sBefore), so -down restores it.
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
				tenant, survivor.id, plan.RaiseTo); err != nil {
				return fmt.Errorf("raise survivor status: %w", err)
			}
		}
		var events []locationEvent
		// The survivor's own service is a location of it.
		ownID, ev, err := ensureMergeLocation(ctx, tx, tenant, survivor.id, survivor, true)
		if err != nil {
			return err
		}
		if ev != nil {
			events = append(events, *ev)
		}
		var audits []locationMergeAudit
		for i, l := range g[1:] {
			// The first journal entry carries what the group changed on the
			// survivor before any loser (its reopen, its own location).
			built := []string{}
			var before []byte
			if i == 0 {
				before = sBefore
				if ownID != "" {
					built = append(built, ownID)
				}
			}
			ev, a, err := foldLoser(ctx, tx, tenant, runID, survivor, l, built, before)
			if err != nil {
				return err
			}
			if ev != nil {
				events = append(events, *ev)
			}
			audits = append(audits, a)
		}
		// Timeline and audit last (the audit chain lock comes after the
		// business rows).
		if err := recordLocationEvents(ctx, tx, tenant, events, "vulnmatch_location_merge", causeLocationMerge.ActorName); err != nil {
			return err
		}
		for _, a := range audits {
			if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
				VALUES (gen_random_uuid(), $1, $2, 'finding', $3, 'success', 'medium', $4, $5::jsonb, NOW())`,
				tenant, string(audit.ActionFindingDuplicateMarked), a.loserID, a.message, a.meta); err != nil {
				return fmt.Errorf("audit location merge: %w", err)
			}
		}
		return nil
	})
}

type locationMergeAudit struct{ loserID, message, meta string }

// sameCandidates reports whether the locked rows are the planned ones, with
// the same status and key.
func sameCandidates(plan, now []mergeCandidate) bool {
	if len(plan) != len(now) {
		return false
	}
	byID := map[string]mergeCandidate{}
	for _, c := range now {
		byID[c.id] = c
	}
	for _, p := range plan {
		c, ok := byID[p.id]
		if !ok || c.status != p.status || c.fingerprint != p.fingerprint || c.closure != p.closure ||
			c.verification != p.verification || c.resolution != p.resolution || c.assignee != p.assignee {
			return false
		}
	}
	return true
}

// ensureMergeLocation makes sure finding findingID has a location for c's
// service (key c.fingerprint): an existing row of findingID is kept, a new
// one gets the state c's status stands for. It returns the new row's id ("" when
// none was built) and the timeline event for a built row of another finding.
func ensureMergeLocation(ctx context.Context, tx *sql.Tx, tenant, findingID string, c mergeCandidate, own bool) (string, *locationEvent, error) {
	var holder string
	err := tx.QueryRowContext(ctx, `SELECT finding_id::text FROM finding_locations WHERE tenant_id = $1 AND location_key = $2`,
		tenant, c.fingerprint).Scan(&holder)
	switch {
	case err == nil:
		if holder != findingID {
			return "", nil, fmt.Errorf("location of finding %s is held by finding %s", c.id, holder)
		}
		return "", nil, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", nil, fmt.Errorf("read location: %w", err)
	}
	state := locationStateOf(c)
	reason := softwarematch.ReasonMerged
	var id string
	if err := tx.QueryRowContext(ctx, `INSERT INTO finding_locations (tenant_id, finding_id, asset_id, location_key, port, transport,
			product_id, version_id, version, link_location, evidence, state, state_reason, first_seen_at, last_seen_at)
		SELECT $1, $2, f.asset_id, $3, COALESCE(f.network_port, 0), $4, $5::uuid, $6::uuid, $7, $8, $9, $10, $11,
		       COALESCE(f.first_detected_at, f.created_at), COALESCE(f.last_seen_at, f.created_at)
		FROM findings f WHERE f.tenant_id = $1 AND f.id = $12
		RETURNING id::text`,
		tenant, findingID, c.fingerprint, clipText(c.transport, 8), uuidOrNil(c.productID), uuidOrNil(c.versionID),
		clipText(c.version, 128), clipText(c.linkLocation, 512), softwarematch.LocationEvidence(c.evidence), string(state), reason,
		c.id).Scan(&id); err != nil {
		return "", nil, fmt.Errorf("build location: %w", err)
	}
	if own {
		return id, nil, nil
	}
	return id, &locationEvent{findingID: findingID, assetID: c.assetID, label: softwarematch.LocationLabel(c.assetName, c.port, c.transport),
		to: string(state), reason: reason, version: c.version}, nil
}

func uuidOrNil(s string) any {
	if _, err := shared.IDFromString(s); err != nil {
		return nil
	}
	return s
}

// foldLoser folds one loser into the survivor and journals it.
func foldLoser(ctx context.Context, tx *sql.Tx, tenant, runID string, survivor, l mergeCandidate, built []string,
	sBefore []byte,
) (*locationEvent, locationMergeAudit, error) {
	var lBefore []byte
	if sBefore == nil {
		if err := tx.QueryRowContext(ctx, `SELECT `+survivorSnapshotSQL+` FROM findings WHERE tenant_id = $1 AND id = $2`,
			tenant, survivor.id).Scan(&sBefore); err != nil {
			return nil, locationMergeAudit{}, fmt.Errorf("snapshot survivor: %w", err)
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT `+loserSnapshotSQL+` FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenant, l.id).Scan(&lBefore); err != nil {
		return nil, locationMergeAudit{}, fmt.Errorf("snapshot loser: %w", err)
	}
	moved := map[string][]json.RawMessage{}
	dropped := map[string][]json.RawMessage{}
	for _, ref := range locationMergeRefs() {
		m, d, err := journalRef(ctx, tx, ref, tenant, survivor.id, l.id)
		if err != nil {
			return nil, locationMergeAudit{}, err
		}
		key := ref.table + "." + ref.column
		if len(m) > 0 {
			moved[key] = m
		}
		if len(d) > 0 {
			dropped[key] = d
		}
		if err := repointRef(ctx, tx, ref, survivor.id, []string{l.id}, tenant); err != nil {
			return nil, locationMergeAudit{}, fmt.Errorf("location merge: %w", err)
		}
	}
	// The loser's service is a location of the survivor: moved with the
	// loser's rows when the matcher already wrote it, built here otherwise.
	locID, ev, err := ensureMergeLocation(ctx, tx, tenant, survivor.id, l, false)
	if err != nil {
		return nil, locationMergeAudit{}, err
	}
	if locID != "" {
		built = append(built, locID)
	} else {
		ev = &locationEvent{findingID: survivor.id, assetID: l.assetID, label: softwarematch.LocationLabel(l.assetName, l.port, l.transport),
			to: string(locationStateOf(l)), reason: softwarematch.ReasonMerged, version: l.version}
	}
	// Tickets and tags are unioned, the earliest detection and SLA deadline
	// of an affected service win, the latest sighting wins. The assignee
	// stays the survivor's; the status is raised in applyGroup.
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings s SET
			work_item_uris = COALESCE(s.work_item_uris, '{}') || ARRAY(
				SELECT u FROM unnest(COALESCE(l.work_item_uris, '{}')) AS u
				WHERE NOT u = ANY(COALESCE(s.work_item_uris, '{}'))),
			tags = COALESCE(s.tags, '{}') || ARRAY(
				SELECT t FROM unnest(COALESCE(l.tags, '{}')) AS t
				WHERE NOT t = ANY(COALESCE(s.tags, '{}'))),
			first_detected_at = LEAST(s.first_detected_at, l.first_detected_at),
			last_seen_at = GREATEST(s.last_seen_at, l.last_seen_at),
			sla_deadline = CASE WHEN $4 AND l.sla_deadline IS NOT NULL AND (s.sla_deadline IS NULL OR l.sla_deadline < s.sla_deadline)
				THEN l.sla_deadline ELSE s.sla_deadline END,
			sla_status = CASE WHEN $4 AND l.sla_deadline IS NOT NULL AND (s.sla_deadline IS NULL OR l.sla_deadline < s.sla_deadline)
				THEN l.sla_status ELSE s.sla_status END,
			duplicate_count = COALESCE(s.duplicate_count, 0) + COALESCE(l.duplicate_count, 0) + 1
		FROM findings l
		WHERE s.id = $1 AND s.tenant_id = $3 AND l.id = $2 AND l.tenant_id = $3`,
		survivor.id, l.id, tenant, locationStateOf(l) == softwarematch.LocationAffected); err != nil {
		return nil, locationMergeAudit{}, fmt.Errorf("inherit finding state: %w", err)
	}
	// The tombstone keeps its id and its own key history (its former key is
	// not an alias of the survivor) and gives up its key.
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET status = 'duplicate', duplicate_of = $1, fingerprint = 'dup:' || id::text,
			resolved_at = COALESCE(resolved_at, NOW()), updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3`, survivor.id, l.id, tenant); err != nil {
		return nil, locationMergeAudit{}, fmt.Errorf("mark merged finding duplicate: %w", err)
	}
	var sAfter []byte
	if err := tx.QueryRowContext(ctx, `SELECT `+survivorSnapshotSQL+` FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenant, survivor.id).Scan(&sAfter); err != nil {
		return nil, locationMergeAudit{}, fmt.Errorf("snapshot survivor: %w", err)
	}
	movedJSON, _ := json.Marshal(moved)
	droppedJSON, _ := json.Marshal(dropped)
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_location_merges (tenant_id, run_id, survivor_id, loser_id,
			survivor_before, survivor_after, loser_before, moved, dropped, built_location_ids, merged_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid[], clock_timestamp())`,
		tenant, runID, survivor.id, l.id, sBefore, sAfter, lBefore, movedJSON, droppedJSON, pq.Array(built)); err != nil {
		return nil, locationMergeAudit{}, fmt.Errorf("journal location merge: %w", err)
	}
	survivorChanges, _ := json.Marshal(map[string]string{"merged_from": l.id, locKeyReason: reasonLocationMerge, "loser_status": l.status})
	loserChanges, _ := json.Marshal(map[string]string{locKeyDupOf: survivor.id, locKeyReason: reasonLocationMerge})
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
		VALUES ($1, $2, 'duplicate_marked', 'system', $3, 'vulnmatch_location_merge', $4),
		       ($1, $5, 'duplicate_marked', 'system', $6, 'vulnmatch_location_merge', $7)`,
		tenant, survivor.id, survivorChanges, "Merged duplicate finding "+l.id+" into this finding (another service of the same host)",
		l.id, loserChanges, "Marked duplicate of "+survivor.id+" by the version-match location merge"); err != nil {
		return nil, locationMergeAudit{}, fmt.Errorf("record location merge activity: %w", err)
	}
	meta, _ := json.Marshal(map[string]string{locKeySurvivor: survivor.id, locKeyLoserID: l.id, "loser_fingerprint": l.fingerprint,
		locKeyReason: reasonLocationMerge, locKeyRunID: runID})
	return ev, locationMergeAudit{loserID: l.id, message: "Finding merged into " + survivor.id + " by the version-match location merge",
		meta: string(meta)}, nil
}

// locationMergeRefs are the finding references a location merge moves:
// every one the finding merge moves except the key history (the loser's keys
// stay with the tombstone, see the file comment).
func locationMergeRefs() []mergeRef {
	out := make([]mergeRef, 0, len(findingMergeRefs))
	for _, ref := range findingMergeRefs {
		if ref.table == "finding_fingerprints" {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// primaryKeyColumns returns the primary key columns of table.
func primaryKeyColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.attname FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE i.indrelid = $1::regclass AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)`, table)
	if err != nil {
		return nil, fmt.Errorf("primary key of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// rowKeySQL is the jsonb expression that identifies a row of ref after the
// move: its primary key without the moved column, or the whole row without
// it when the moved column is the whole key.
func rowKeySQL(ref mergeRef, pk []string, alias string) string {
	var cols []string
	for _, c := range pk {
		if c != ref.column {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return fmt.Sprintf("(to_jsonb(%s) - '%s')", alias, ref.column)
	}
	parts := make([]string, 0, 2*len(cols))
	for _, c := range cols {
		parts = append(parts, fmt.Sprintf("'%s', %s.%s", c, alias, c))
	}
	return "jsonb_build_object(" + strings.Join(parts, ", ") + ")"
}

// journalRef records, before ref is moved, the keys of the loser's rows that
// will move and the whole rows that will be dropped (the survivor already
// has their unique key).
func journalRef(ctx context.Context, tx *sql.Tx, ref mergeRef, tenant, survivorID, loserID string) (moved, dropped []json.RawMessage, err error) {
	pk, err := primaryKeyColumns(ctx, tx, ref.table)
	if err != nil {
		return nil, nil, err
	}
	// A table without a primary key is identified by its whole row (less the
	// moved column), which its unique merge key keeps distinct.
	if len(pk) == 0 && len(ref.keys) == 0 {
		return nil, nil, fmt.Errorf("location merge: %s has no primary key and no unique key", ref.table)
	}
	scope, kScope := "", ""
	args := []any{loserID, survivorID}
	if ref.tenantCol != "" {
		scope = fmt.Sprintf(" AND m.%s = $3", ref.tenantCol)
		kScope = fmt.Sprintf(" AND k.%s = $3", ref.tenantCol)
		args = append(args, tenant)
	}
	conflict := "($2::uuid IS NULL)" // no unique key: nothing is dropped
	if len(ref.keys) > 0 {
		var ors []string
		for _, k := range ref.keys {
			ors = append(ors, fmt.Sprintf("EXISTS (SELECT 1 FROM %s k WHERE k.%s = $2%s AND %s)", ref.table, ref.column, kScope, keyMatch(k, "k", "m")))
		}
		conflict = "(" + strings.Join(ors, " OR ") + ")"
	}
	//nolint:gosec // G201: identifiers come from the fixed findingMergeRefs list and the catalog, never user input.
	q := fmt.Sprintf(`SELECT %[4]s, %[5]s, to_jsonb(m) FROM %[1]s m WHERE m.%[2]s = $1%[3]s`,
		ref.table, ref.column, scope, conflict, rowKeySQL(ref, pk, "m"))
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("journal %s.%s: %w", ref.table, ref.column, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var drop bool
		var key, row []byte
		if err := rows.Scan(&drop, &key, &row); err != nil {
			return nil, nil, err
		}
		if drop {
			dropped = append(dropped, row)
		} else {
			moved = append(moved, key)
		}
	}
	return moved, dropped, rows.Err()
}

// LocationRevertEntry is one journaled fold and what its revert did.
type LocationRevertEntry struct {
	SurvivorID string `json:"survivor_id"`
	LoserID    string `json:"loser_id"`
	Reverted   bool   `json:"reverted"`
	Skipped    string `json:"skipped,omitempty"`
	// Kept lists survivor columns changed since the fold, left as they are.
	Kept []string `json:"kept,omitempty"`
}

// LocationRevertReport is what one tenant's revert did, or would do.
type LocationRevertReport struct {
	TenantID string                `json:"tenant_id"`
	Applied  bool                  `json:"applied"`
	Entries  []LocationRevertEntry `json:"entries"`
	Reverted int                   `json:"reverted"`
	Skipped  int                   `json:"skipped"`
}

// RevertLocationMerges restores the tenant's journaled folds (of run runID,
// or of every run when empty), newest first. The loser gets back its status,
// key and every row that moved; dropped rows are put back; the locations the
// fold built are removed; each survivor column the fold changed goes back
// unless it changed again since. Without apply it only reports.
func (r *LocationMergeRepository) RevertLocationMerges(ctx context.Context, tenantID shared.ID, runID string, apply bool) (*LocationRevertReport, error) {
	tenant := tenantID.String()
	rep := &LocationRevertReport{TenantID: tenant, Applied: apply, Entries: []LocationRevertEntry{}}
	rows, err := r.db.QueryContext(ctx, `SELECT id::text, survivor_id::text, loser_id::text FROM finding_location_merges
		WHERE tenant_id = $1 AND reverted_at IS NULL AND ($2 = '' OR run_id::text = $2)
		ORDER BY merged_at DESC, id DESC`, tenant, runID)
	if err != nil {
		return nil, fmt.Errorf("list location merges: %w", err)
	}
	type entry struct{ id, survivor, loser string }
	var list []entry
	err = func() error {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var e entry
			if err := rows.Scan(&e.id, &e.survivor, &e.loser); err != nil {
				return err
			}
			list = append(list, e)
		}
		return rows.Err()
	}()
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		out := LocationRevertEntry{SurvivorID: e.survivor, LoserID: e.loser}
		err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
			skipped, kept, err := revertOne(ctx, tx, tenant, e.id, apply)
			out.Skipped, out.Kept = skipped, kept
			if err != nil {
				return err
			}
			if !apply || skipped != "" {
				return errRollbackRevert
			}
			return nil
		})
		switch {
		case errors.Is(err, errRollbackRevert):
		case err != nil:
			return nil, err
		default:
			out.Reverted = true
		}
		switch {
		case out.Skipped != "":
			rep.Skipped++
		case out.Reverted || !apply:
			// Reverted, or (dry run) would be.
			rep.Reverted++
		}
		rep.Entries = append(rep.Entries, out)
	}
	return rep, nil
}

// errRollbackRevert rolls back a dry run (or a skipped entry) of one revert.
var errRollbackRevert = errors.New("revert rolled back")

// Revert skip reasons.
const (
	RevertSkipLoserChanged = "loser_changed_since_merge"
	RevertSkipKeyTaken     = "key_taken_since_merge"
)

func revertOne(ctx context.Context, tx *sql.Tx, tenant, entryID string, apply bool) (string, []string, error) {
	if apply {
		if err := setFindingTransition(ctx, tx, findingTransition{Source: vulnmatchSource, Reason: reasonLocationMergeReverted,
			ActorName: "system: version-match location merge", Message: "The version-match location merge was reverted"}); err != nil {
			return "", nil, err
		}
	}
	var survivorID, loserID, runID string
	var sBefore, sAfter, lBefore, movedRaw, droppedRaw []byte
	var built []string
	if err := tx.QueryRowContext(ctx, `SELECT survivor_id::text, loser_id::text, run_id::text, survivor_before, survivor_after, loser_before,
			moved, dropped, built_location_ids::text[]
		FROM finding_location_merges WHERE tenant_id = $1 AND id = $2 AND reverted_at IS NULL FOR UPDATE`,
		tenant, entryID).Scan(&survivorID, &loserID, &runID, &sBefore, &sAfter, &lBefore, &movedRaw, &droppedRaw, pq.Array(&built)); err != nil {
		return "", nil, fmt.Errorf("read location merge: %w", err)
	}
	var lb struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(lBefore, &lb); err != nil {
		return "", nil, fmt.Errorf("read location merge: %w", err)
	}
	// The loser must still be this fold's tombstone, and its key free.
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT status = 'duplicate' AND duplicate_of IS NOT DISTINCT FROM $3::uuid
			AND fingerprint = 'dup:' || id::text
		FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenant, loserID, survivorID).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !ok) {
		return RevertSkipLoserChanged, nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("check tombstone: %w", err)
	}
	var taken bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM findings WHERE tenant_id = $1 AND fingerprint = $2)`,
		tenant, lb.Fingerprint).Scan(&taken); err != nil {
		return "", nil, fmt.Errorf("check key: %w", err)
	}
	if taken {
		return RevertSkipKeyTaken, nil, nil
	}
	// Survivor columns changed again since the fold are kept as they are.
	var kept []string
	checks := make([]string, 0, len(survivorRestoreColumns))
	for _, c := range survivorRestoreColumns {
		checks = append(checks, fmt.Sprintf("CASE WHEN f.%[1]s IS DISTINCT FROM a.%[1]s AND a.%[1]s IS DISTINCT FROM b.%[1]s THEN '%[1]s' END", c))
	}
	//nolint:gosec // G201: the columns come from the fixed survivorRestoreColumns list.
	q := `SELECT array_remove(ARRAY[` + strings.Join(checks, ", ") + `]::text[], NULL)
		FROM findings f, jsonb_populate_record(NULL::findings, $3::jsonb) b, jsonb_populate_record(NULL::findings, $4::jsonb) a
		WHERE f.tenant_id = $1 AND f.id = $2 FOR UPDATE OF f`
	if err := tx.QueryRowContext(ctx, q, tenant, survivorID, string(sBefore), string(sAfter)).Scan(pq.Array(&kept)); err != nil {
		return "", nil, fmt.Errorf("compare survivor: %w", err)
	}
	if !apply {
		return "", kept, nil
	}
	// Built locations go; moved rows (locations included) go back; dropped
	// rows are put back.
	if len(built) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM finding_locations WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
			tenant, pq.Array(built)); err != nil {
			return "", nil, fmt.Errorf("remove built locations: %w", err)
		}
	}
	var moved, dropped map[string][]json.RawMessage
	if err := json.Unmarshal(movedRaw, &moved); err != nil {
		return "", nil, err
	}
	if err := json.Unmarshal(droppedRaw, &dropped); err != nil {
		return "", nil, err
	}
	for _, ref := range locationMergeRefs() {
		key := ref.table + "." + ref.column
		if keys := moved[key]; len(keys) > 0 {
			if err := moveBack(ctx, tx, ref, tenant, survivorID, loserID, keys); err != nil {
				return "", nil, err
			}
		}
		for _, row := range dropped[key] {
			//nolint:gosec // G201: the table comes from the fixed findingMergeRefs list.
			q := fmt.Sprintf(`INSERT INTO %[1]s SELECT * FROM jsonb_populate_record(NULL::%[1]s, $1::jsonb) ON CONFLICT DO NOTHING`, ref.table)
			if _, err := tx.ExecContext(ctx, q, string(row)); err != nil {
				return "", nil, fmt.Errorf("restore %s row: %w", ref.table, err)
			}
		}
	}
	// The loser gets back its status and key.
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings f SET status = b.status, resolution = b.resolution, closure_reason = b.closure_reason,
			verification = b.verification, resolved_at = b.resolved_at, resolved_by = b.resolved_by,
			fingerprint = b.fingerprint, duplicate_of = b.duplicate_of, updated_at = NOW()
		FROM jsonb_populate_record(NULL::findings, $3::jsonb) b
		WHERE f.tenant_id = $1 AND f.id = $2`, tenant, loserID, string(lBefore)); err != nil {
		return "", nil, fmt.Errorf("restore loser: %w", err)
	}
	// Each survivor column the fold changed goes back, unless it changed
	// again since the fold. SLA deadlines only ever tighten
	// (guard_sla_deadline_tighten_only); a revert puts back the deadline the
	// survivor had before the fold took a loser's earlier one, so it says so
	// for this transaction.
	if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.sla_restart', 'on', true)`); err != nil {
		return "", nil, fmt.Errorf("allow deadline restore: %w", err)
	}
	sets := make([]string, 0, len(survivorRestoreColumns))
	for _, c := range survivorRestoreColumns {
		sets = append(sets, fmt.Sprintf("%[1]s = CASE WHEN f.%[1]s IS NOT DISTINCT FROM a.%[1]s THEN b.%[1]s ELSE f.%[1]s END", c))
	}
	//nolint:gosec // G201: the columns come from the fixed survivorRestoreColumns list.
	upd := `UPDATE findings f SET ` + strings.Join(sets, ", ") + `, updated_at = NOW()
		FROM jsonb_populate_record(NULL::findings, $3::jsonb) b, jsonb_populate_record(NULL::findings, $4::jsonb) a
		WHERE f.tenant_id = $1 AND f.id = $2`
	if _, err := tx.ExecContext(ctx, upd, tenant, survivorID, string(sBefore), string(sAfter)); err != nil {
		return "", nil, fmt.Errorf("restore survivor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_location_merges SET reverted_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenant, entryID); err != nil {
		return "", nil, fmt.Errorf("close location merge: %w", err)
	}
	changes, _ := json.Marshal(map[string]string{locKeyDupOf: survivorID, locKeyReason: reasonLocationMergeReverted})
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
		VALUES ($1, $2, 'duplicate_unmarked', 'system', $3, 'vulnmatch_location_merge', $4),
		       ($1, $5, 'duplicate_unmarked', 'system', $3, 'vulnmatch_location_merge', $6)`,
		tenant, loserID, changes, "No longer a duplicate of "+survivorID+": the version-match location merge was reverted",
		survivorID, "Finding "+loserID+" is its own finding again: the version-match location merge was reverted"); err != nil {
		return "", nil, fmt.Errorf("record revert activity: %w", err)
	}
	meta, _ := json.Marshal(map[string]any{locKeySurvivor: survivorID, locKeyLoserID: loserID, locKeyRunID: runID,
		locKeyReason: reasonLocationMergeReverted, "kept_columns": kept})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
		VALUES (gen_random_uuid(), $1, $2, 'finding', $3, 'success', 'medium', $4, $5::jsonb, NOW())`,
		tenant, string(audit.ActionFindingLocationChanged), loserID, "Version-match location merge reverted", string(meta)); err != nil {
		return "", nil, fmt.Errorf("audit revert: %w", err)
	}
	return "", kept, nil
}

// moveBack moves the journaled rows of ref from the survivor back to the
// loser.
func moveBack(ctx context.Context, tx *sql.Tx, ref mergeRef, tenant, survivorID, loserID string, keys []json.RawMessage) error {
	pk, err := primaryKeyColumns(ctx, tx, ref.table)
	if err != nil {
		return err
	}
	arr := make([]string, len(keys))
	for i, k := range keys {
		arr[i] = string(k)
	}
	args := []any{loserID, survivorID, pq.Array(arr)}
	scope := ""
	if ref.tenantCol != "" {
		scope = fmt.Sprintf(" AND m.%s = $4", ref.tenantCol)
		args = append(args, tenant)
	}
	//nolint:gosec // G201: identifiers come from the fixed findingMergeRefs list and the catalog, never user input.
	q := fmt.Sprintf(`UPDATE %[1]s m SET %[2]s = $1 WHERE m.%[2]s = $2%[3]s AND %[4]s = ANY($3::jsonb[])`,
		ref.table, ref.column, scope, rowKeySQL(ref, pk, "m"))
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("move back %s.%s: %w", ref.table, ref.column, err)
	}
	return nil
}

// LocationMergeTenants lists the tenants that have version-match findings on
// service assets (merge) or open journal entries (revert).
func (r *LocationMergeRepository) LocationMergeTenants(ctx context.Context, revert bool) ([]shared.ID, error) {
	q := `SELECT DISTINCT f.tenant_id::text FROM findings f JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		WHERE ` + matcherOwnedSQL + ` AND f.status <> 'duplicate' AND a.asset_type = 'service'
		ORDER BY 1`
	if revert {
		q = `SELECT DISTINCT tenant_id::text FROM finding_location_merges WHERE reverted_at IS NULL ORDER BY 1`
	}
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, shared.MustIDFromString(id))
	}
	return out, rows.Err()
}
