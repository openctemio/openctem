// Package vex manages the organization's VEX statements and applies them to
// findings: on create, edit, delete and expiry, and to findings ingest
// creates later (sticky). Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.
//
// Threat model: a statement closes findings, so it is a way to hide real
// risk. Writes need findings:approve (the route), an asset-bound statement
// needs the asset in the caller's data scope, a statement for every asset
// needs full data access (it closes findings on assets the caller cannot
// see), human-sourced findings are never closed, and every write, expiry
// and closure is audited.
package vex

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	vexdom "github.com/openctemio/openctem/api/pkg/domain/vex"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AuditLogger records audit events.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// ScopeResolver is the caller's data scope (datascope.Enforcer).
type ScopeResolver interface {
	Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
	AssertAsset(ctx context.Context, tenantID, assetID shared.ID) error
}

var _ ScopeResolver = (*datascope.Enforcer)(nil)

// applyBatch is how many findings one transaction updates.
const applyBatch = 1000

// maxAuditedIDs bounds the finding ids an audit event lists.
const maxAuditedIDs = 100

// ErrFullDataRequired refuses a statement for every asset from a member
// restricted to part of the tenant.
var ErrFullDataRequired = fmt.Errorf("%w: a statement for every asset needs access to every asset; choose an asset", shared.ErrForbidden)

// Service manages VEX statements.
type Service struct {
	repo   vexdom.Repository
	scope  ScopeResolver
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
}

// NewService creates the service. scope nil leaves reads and writes
// tenant-wide (tests and internal callers).
func NewService(repo vexdom.Repository, scope ScopeResolver, audit AuditLogger, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, scope: scope, audit: audit, logger: log, now: time.Now}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// ApplyResult is what applying a statement change did to findings.
type ApplyResult struct {
	Matched  int `json:"matched"`
	Closed   int `json:"closed"`
	Reopened int `json:"reopened"`
	// FindingIDs whose status moved (at most 100).
	FindingIDs []string `json:"finding_ids,omitempty"`
}

func (r *ApplyResult) add(o ApplyResult) {
	r.Matched += o.Matched
	r.Closed += o.Closed
	r.Reopened += o.Reopened
	for _, id := range o.FindingIDs {
		if len(r.FindingIDs) < maxAuditedIDs {
			r.FindingIDs = append(r.FindingIDs, id)
		}
	}
}

// Input is the content of a statement to create or edit.
type Input struct {
	VulnID string
	// ProductID or PURL names the package (create only).
	ProductID       string
	PURL            string
	AssetID         string
	Versions        []string
	VersionRange    string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	ExpiresAt       *time.Time
}

// Patch is an edit of a statement's content; nil fields keep their value.
// ClearExpiry removes the expiry.
type Patch struct {
	Versions        *[]string
	VersionRange    *string
	Status          *string
	Justification   *string
	ImpactStatement *string
	ActionStatement *string
	ExpiresAt       *time.Time
	ClearExpiry     bool
}

func (p *Patch) apply(st *vexdom.Statement) {
	if p.Versions != nil {
		st.Versions = *p.Versions
		if p.VersionRange == nil {
			st.VersionRange = ""
		}
	}
	if p.VersionRange != nil {
		st.VersionRange = *p.VersionRange
		if p.Versions == nil {
			st.Versions = nil
		}
	}
	if p.Status != nil {
		st.Status = vexdom.Status(*p.Status)
		if st.Status != vexdom.StatusNotAffected && p.Justification == nil {
			st.Justification = ""
		}
	}
	if p.Justification != nil {
		st.Justification = *p.Justification
	}
	if p.ImpactStatement != nil {
		st.ImpactStatement = *p.ImpactStatement
	}
	if p.ActionStatement != nil {
		st.ActionStatement = *p.ActionStatement
	}
	switch {
	case p.ClearExpiry:
		st.ExpiresAt = nil
	case p.ExpiresAt != nil:
		st.ExpiresAt = p.ExpiresAt
	}
}

func (s *Service) callerScope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	if s.scope == nil {
		return nil, nil
	}
	return s.scope.Resolve(ctx, tenantID)
}

// authorizeSubject checks the caller may write a statement about assetID
// (nil: every asset).
func (s *Service) authorizeSubject(ctx context.Context, tenantID shared.ID, assetID *shared.ID) error {
	if s.scope == nil {
		return nil
	}
	if assetID != nil {
		return s.scope.AssertAsset(ctx, tenantID, *assetID)
	}
	scope, err := s.scope.Resolve(ctx, tenantID)
	if err != nil {
		return err
	}
	// Any scope, including an Unrestricted one (an administrator who does
	// not see some private program assets), means the caller cannot see
	// every asset the statement would act on.
	if scope != nil {
		return ErrFullDataRequired
	}
	return nil
}

// canRead reports whether the caller may see the statement: an asset-bound
// one when the asset is in scope, one for every asset when an in-scope
// asset uses the package.
func (s *Service) canRead(ctx context.Context, st *vexdom.Statement) error {
	if s.scope == nil {
		return nil
	}
	if st.AssetID != nil {
		if err := s.scope.AssertAsset(ctx, st.TenantID, *st.AssetID); err != nil {
			return vexdom.ErrNotFound
		}
		return nil
	}
	scope, err := s.scope.Resolve(ctx, st.TenantID)
	if err != nil {
		return err
	}
	if scope == nil {
		return nil
	}
	ok, err := s.repo.ProductInScope(ctx, st.TenantID, st.ProductID, scope)
	if err != nil {
		return err
	}
	if !ok {
		return vexdom.ErrNotFound
	}
	return nil
}

func parseOptionalID(v, field string) (*shared.ID, error) {
	if v == "" {
		return nil, nil
	}
	id, err := shared.IDFromString(v)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", shared.ErrValidation, field)
	}
	return &id, nil
}

func (s *Service) resolveProduct(ctx context.Context, tenantID shared.ID, in Input) (shared.ID, error) {
	switch {
	case in.ProductID != "":
		id, err := shared.IDFromString(in.ProductID)
		if err != nil {
			return shared.ID{}, fmt.Errorf("%w: invalid product_id", shared.ErrValidation)
		}
		ok, err := s.repo.ProductVisible(ctx, tenantID, id)
		if err != nil {
			return shared.ID{}, err
		}
		if !ok {
			return shared.ID{}, fmt.Errorf("%w: package not found", shared.ErrNotFound)
		}
		return id, nil
	case in.PURL != "":
		p, err := software.ParsePURL(in.PURL)
		if err != nil {
			return shared.ID{}, fmt.Errorf("%w: invalid purl", shared.ErrValidation)
		}
		return s.repo.ResolveProduct(ctx, tenantID, p.Type, p.Namespace, p.Name)
	}
	return shared.ID{}, fmt.Errorf("%w: product_id or purl is required", shared.ErrValidation)
}

// Create stores a statement and applies it to the findings it covers.
func (s *Service) Create(ctx context.Context, tenantID shared.ID, in Input, actx auditapp.AuditContext) (*vexdom.Statement, ApplyResult, error) {
	assetID, err := parseOptionalID(in.AssetID, "asset_id")
	if err != nil {
		return nil, ApplyResult{}, err
	}
	if err := s.authorizeSubject(ctx, tenantID, assetID); err != nil {
		return nil, ApplyResult{}, err
	}
	productID, err := s.resolveProduct(ctx, tenantID, in)
	if err != nil {
		return nil, ApplyResult{}, err
	}
	st := &vexdom.Statement{
		ID: shared.NewID(), TenantID: tenantID, VulnID: in.VulnID, ProductID: productID, AssetID: assetID,
		Versions: in.Versions, VersionRange: in.VersionRange, Status: vexdom.Status(in.Status),
		Justification: in.Justification, ImpactStatement: in.ImpactStatement, ActionStatement: in.ActionStatement,
		Origin: vexdom.OriginManual, ExpiresAt: in.ExpiresAt, CreatedBy: actorID(actx),
	}
	if err := st.Normalize(s.now()); err != nil {
		return nil, ApplyResult{}, err
	}
	if err := s.repo.Create(ctx, st); err != nil {
		return nil, ApplyResult{}, err
	}
	res, err := s.applySubject(ctx, st)
	s.auditStatement(ctx, actx, auditdom.ActionVEXStatementCreated, st, nil, res, err)
	if err != nil {
		return st, res, fmt.Errorf("apply vex statement: %w", err)
	}
	return st, res, nil
}

// Update edits a statement's content (status, justification, statements,
// versions, expiry) and re-applies it. Its subject (vulnerability, package,
// asset) is fixed: a different subject is a new statement.
func (s *Service) Update(ctx context.Context, tenantID shared.ID, id string, in Patch, actx auditapp.AuditContext) (*vexdom.Statement, ApplyResult, error) {
	sid, err := shared.IDFromString(id)
	if err != nil {
		return nil, ApplyResult{}, vexdom.ErrNotFound
	}
	st, err := s.repo.Get(ctx, tenantID, sid)
	if err != nil {
		return nil, ApplyResult{}, err
	}
	if err := s.canRead(ctx, st); err != nil {
		return nil, ApplyResult{}, err
	}
	if err := s.authorizeSubject(ctx, tenantID, st.AssetID); err != nil {
		return nil, ApplyResult{}, err
	}
	before := *st
	in.apply(st)
	st.UpdatedBy = actorID(actx)
	if err := st.Normalize(s.now()); err != nil {
		return nil, ApplyResult{}, err
	}
	if err := s.repo.Update(ctx, st); err != nil {
		return nil, ApplyResult{}, err
	}
	res, err := s.applySubject(ctx, st)
	if err == nil {
		// Findings the edited statement no longer covers (versions narrowed).
		var r2 ApplyResult
		r2, err = s.withdraw(ctx, st, nil)
		res.add(r2)
	}
	s.auditStatement(ctx, actx, auditdom.ActionVEXStatementUpdated, st, &before, res, err)
	if err != nil {
		return st, res, fmt.Errorf("apply vex statement: %w", err)
	}
	return st, res, nil
}

// Delete removes a statement; the findings it closed reopen unless another
// statement covers them.
func (s *Service) Delete(ctx context.Context, tenantID shared.ID, id string, actx auditapp.AuditContext) (ApplyResult, error) {
	sid, err := shared.IDFromString(id)
	if err != nil {
		return ApplyResult{}, vexdom.ErrNotFound
	}
	st, err := s.repo.Get(ctx, tenantID, sid)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := s.canRead(ctx, st); err != nil {
		return ApplyResult{}, err
	}
	if err := s.authorizeSubject(ctx, tenantID, st.AssetID); err != nil {
		return ApplyResult{}, err
	}
	res, err := s.withdraw(ctx, st, &st.ID)
	if err != nil {
		s.auditStatement(ctx, actx, auditdom.ActionVEXStatementDeleted, st, nil, res, err)
		return res, fmt.Errorf("withdraw vex statement: %w", err)
	}
	if err := s.repo.Delete(ctx, tenantID, sid); err != nil {
		return res, err
	}
	s.auditStatement(ctx, actx, auditdom.ActionVEXStatementDeleted, st, nil, res, nil)
	return res, nil
}

// Get returns a statement the caller may see.
func (s *Service) Get(ctx context.Context, tenantID shared.ID, id string) (*vexdom.Statement, error) {
	sid, err := shared.IDFromString(id)
	if err != nil {
		return nil, vexdom.ErrNotFound
	}
	st, err := s.repo.Get(ctx, tenantID, sid)
	if err != nil {
		return nil, err
	}
	if err := s.canRead(ctx, st); err != nil {
		return nil, err
	}
	return st, nil
}

// ListInput filters the list.
type ListInput struct {
	VulnID    string
	ProductID string
	AssetID   string
	Status    string
}

// List returns the statements the caller may see.
func (s *Service) List(ctx context.Context, tenantID shared.ID, in ListInput, page pagination.Pagination) (pagination.Result[*vexdom.Statement], error) {
	f := vexdom.Filter{TenantID: tenantID}
	var err error
	if in.VulnID != "" {
		if f.VulnID, err = vexdom.NormalizeVulnID(in.VulnID); err != nil {
			return pagination.Result[*vexdom.Statement]{}, err
		}
	}
	if f.ProductID, err = parseOptionalID(in.ProductID, "product_id"); err != nil {
		return pagination.Result[*vexdom.Statement]{}, err
	}
	if f.AssetID, err = parseOptionalID(in.AssetID, "asset_id"); err != nil {
		return pagination.Result[*vexdom.Statement]{}, err
	}
	if in.Status != "" {
		f.Status = vexdom.Status(in.Status)
		if !f.Status.IsValid() {
			return pagination.Result[*vexdom.Statement]{}, fmt.Errorf("%w: unknown status", shared.ErrValidation)
		}
	}
	if f.Scope, err = s.callerScope(ctx, tenantID); err != nil {
		return pagination.Result[*vexdom.Statement]{}, err
	}
	return s.repo.List(ctx, f, page)
}

// applySubject reconciles every finding the statement's subject covers.
func (s *Service) applySubject(ctx context.Context, st *vexdom.Statement) (ApplyResult, error) {
	var total ApplyResult
	after := shared.ID{}
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		refs, err := s.repo.CandidateFindings(ctx, st.TenantID, st.ProductID, st.VulnID, st.AssetID, after, applyBatch)
		if err != nil {
			return total, err
		}
		if len(refs) == 0 {
			return total, nil
		}
		r, err := s.reconcile(ctx, st.TenantID, refs, nil)
		total.add(r)
		if err != nil {
			return total, err
		}
		if len(refs) < applyBatch {
			return total, nil
		}
		after = refs[len(refs)-1].ID
	}
}

// withdraw reconciles the findings that carry the statement; with exclude
// set the statement no longer counts (being deleted).
func (s *Service) withdraw(ctx context.Context, st *vexdom.Statement, exclude *shared.ID) (ApplyResult, error) {
	var total ApplyResult
	after := shared.ID{}
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		refs, err := s.repo.FindingsWithStatement(ctx, st.TenantID, st.ID, after, applyBatch)
		if err != nil {
			return total, err
		}
		if len(refs) == 0 {
			return total, nil
		}
		r, err := s.reconcile(ctx, st.TenantID, refs, exclude)
		total.add(r)
		if err != nil {
			return total, err
		}
		if len(refs) < applyBatch {
			return total, nil
		}
		after = refs[len(refs)-1].ID
	}
}

// reconcile gives each finding the effect of the statement that governs it
// now (excluding exclude).
func (s *Service) reconcile(ctx context.Context, tenantID shared.ID, refs []vexdom.FindingRef, exclude *shared.ID) (ApplyResult, error) {
	seen := map[shared.ID]bool{}
	products := make([]shared.ID, 0, 4)
	for i := range refs {
		if !seen[refs[i].ProductID] {
			seen[refs[i].ProductID] = true
			products = append(products, refs[i].ProductID)
		}
	}
	now := s.now()
	stmts, err := s.repo.ActiveForProducts(ctx, tenantID, products, now)
	if err != nil {
		return ApplyResult{}, err
	}
	if exclude != nil {
		kept := stmts[:0]
		for _, st := range stmts {
			if st.ID != *exclude {
				kept = append(kept, st)
			}
		}
		stmts = kept
	}
	effects := make([]vexdom.Effect, 0, len(refs))
	res := ApplyResult{}
	for i := range refs {
		w := vexdom.Pick(stmts, &refs[i], now)
		if w != nil {
			res.Matched++
		}
		if e := vexdom.Decide(&refs[i], w); e != nil {
			effects = append(effects, *e)
		}
	}
	moved, err := s.repo.WriteEffects(ctx, tenantID, effects)
	if err != nil {
		return res, err
	}
	movedSet := make(map[shared.ID]bool, len(moved))
	for _, id := range moved {
		movedSet[id] = true
	}
	for i := range effects {
		e := &effects[i]
		if !movedSet[e.FindingID] {
			continue
		}
		if e.NewStatus == string(vulnerability.FindingStatusFalsePositive) || e.NewStatus == string(vulnerability.FindingStatusResolved) {
			res.Closed++
		} else {
			res.Reopened++
		}
		if len(res.FindingIDs) < maxAuditedIDs {
			res.FindingIDs = append(res.FindingIDs, e.FindingID.String())
		}
	}
	return res, nil
}

// ApplyToFingerprints applies the tenant's statements to findings an
// ingest just wrote (the sticky rule): a finding a statement covers is
// closed or annotated as if the statement had been made after it.
// Best-effort for the caller; returns the number of findings whose status
// moved.
func (s *Service) ApplyToFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (int, error) {
	if len(fingerprints) == 0 {
		return 0, nil
	}
	has, err := s.repo.TenantHasActive(ctx, tenantID, s.now())
	if err != nil || !has {
		return 0, err
	}
	var total ApplyResult
	for start := 0; start < len(fingerprints); start += applyBatch {
		end := min(start+applyBatch, len(fingerprints))
		refs, err := s.repo.FindingsByFingerprints(ctx, tenantID, fingerprints[start:end])
		if err != nil {
			return total.Closed + total.Reopened, err
		}
		r, err := s.reconcile(ctx, tenantID, refs, nil)
		total.add(r)
		if err != nil {
			return total.Closed + total.Reopened, err
		}
	}
	if n := total.Closed + total.Reopened; n > 0 {
		ev := auditapp.NewSuccessEvent(auditdom.ActionVEXStatementApplied, auditdom.ResourceTypeVEXStatement, "").
			WithMessage("VEX statements applied to newly reported findings").
			WithMetadata("closed", total.Closed).WithMetadata("reopened", total.Reopened).
			WithMetadata("finding_ids", total.FindingIDs)
		s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, ev)
	}
	return total.Closed + total.Reopened, nil
}

// ExpireDue withdraws statements whose expiry passed: their findings
// reopen unless another statement covers them. Runs across tenants
// (system controller); returns the number of statements expired.
func (s *Service) ExpireDue(ctx context.Context, limit int) (int, error) {
	now := s.now()
	due, err := s.repo.DueForExpiry(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, st := range due {
		res, err := s.withdraw(ctx, st, nil)
		if err != nil {
			s.logger.Error("vex statement expiry failed", "tenant_id", st.TenantID.String(), "statement_id", st.ID.String(), "error", err)
			continue
		}
		if err := s.repo.MarkExpired(ctx, st.TenantID, st.ID, now); err != nil {
			return n, err
		}
		s.auditStatement(ctx, auditapp.AuditContext{TenantID: st.TenantID.String()}, auditdom.ActionVEXStatementExpired, st, nil, res, nil)
		n++
	}
	return n, nil
}

func actorID(actx auditapp.AuditContext) *shared.ID {
	if actx.ActorID == "" {
		return nil
	}
	id, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return nil
	}
	return &id
}

func describe(st *vexdom.Statement) map[string]any {
	d := map[string]any{
		"vuln_id": st.VulnID, "product_id": st.ProductID.String(), "status": string(st.Status),
		"justification": st.Justification, "versions": st.Versions, "version_range": st.VersionRange,
		"origin": st.Origin,
	}
	if st.AssetID != nil {
		d["asset_id"] = st.AssetID.String()
	}
	if st.ExpiresAt != nil {
		d["expires_at"] = st.ExpiresAt.Format(time.RFC3339)
	}
	return d
}

func (s *Service) auditStatement(ctx context.Context, actx auditapp.AuditContext, action auditdom.Action,
	st *vexdom.Statement, before *vexdom.Statement, res ApplyResult, opErr error) {
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeVEXStatement, st.ID.String()).
		WithResourceName(st.VulnID).
		WithMessage(fmt.Sprintf("VEX statement %s for %s: %s", action.String(), st.VulnID, st.Status)).
		WithMetadata("statement", describe(st)).
		WithMetadata("closed", res.Closed).
		WithMetadata("reopened", res.Reopened).
		WithMetadata("finding_ids", res.FindingIDs)
	if before != nil {
		ev = ev.WithMetadata("before", describe(before))
	}
	if opErr != nil {
		ev = ev.WithMetadata("apply_error", "applying the statement to findings did not finish")
	}
	s.logAudit(ctx, actx, ev)
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("failed to record vex audit event", "action", string(ev.Action), "error", err)
	}
}

// IsForbidden reports whether err refuses the caller.
func IsForbidden(err error) bool { return errors.Is(err, shared.ErrForbidden) }
