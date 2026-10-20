// Package retestcheck is the domain of a finding's retest check: the custom
// check a person attaches to a finding so that its retest re-runs it
// (docs/architecture/finding-retest-checks.md). The check's content is a
// template of the organization's template library (scanner_templates); the
// check adds who may run it (approval for intrusive checks) and whether it
// has proven it can see the issue (calibration).
package retestcheck

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is how the check was written.
type Kind string

const (
	// KindNuclei: a nuclei template written (or picked from the library) by
	// a person.
	KindNuclei Kind = "nuclei"
	// KindHTTPAssertion: a declarative request and matchers, compiled to a
	// nuclei template by the platform.
	KindHTTPAssertion Kind = "http_assertion"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindNuclei || k == KindHTTPAssertion }

// Tiers (the content pack tiers): T2 checks change state, call out of band
// or send many requests, and need approval before they run.
const (
	TierT0 = "T0"
	TierT1 = "T1"
	TierT2 = "T2"
)

// Errors (the handler answers them with their code).
var (
	ErrApprovalNotNeeded = shared.NewDomainError("RETEST_CHECK_APPROVAL_NOT_NEEDED",
		"this check is not intrusive and needs no approval", shared.ErrConflict)
	ErrAuthorCannotApprove = shared.NewDomainError("RETEST_CHECK_AUTHOR_CANNOT_APPROVE",
		"the person who wrote this version of the check cannot approve it", shared.ErrConflict)
)

// Check is a finding's retest check.
type Check struct {
	ID         shared.ID
	TenantID   shared.ID
	FindingID  shared.ID
	TemplateID shared.ID
	Kind       Kind
	// Assertion is the declarative spec of a KindHTTPAssertion check (the
	// template content is compiled from it).
	Assertion *HTTPAssertion
	// OwnsTemplate: the template was created for this check (editing the
	// check edits it). A template picked from the library is never edited
	// from a finding.
	OwnsTemplate bool
	Tier         string
	TierReason   string
	// ApprovedDigest is the template digest a second person approved
	// (T2 checks); approval is bound to the bytes it was given for.
	ApprovedDigest string
	ApprovedBy     *shared.ID
	ApprovedAt     *time.Time
	// CalibratedDigest is the template digest that matched this finding
	// once: only then does a no-match prove a fix.
	CalibratedDigest string
	CalibratedAt     *time.Time
	// AuthorID wrote the current content version (it cannot approve it).
	AuthorID  *shared.ID
	CreatedBy *shared.ID
	UpdatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NeedsApproval reports whether the check is intrusive.
func (c *Check) NeedsApproval() bool { return c.Tier == TierT2 }

// Approved reports whether the check may run with content digest.
func (c *Check) Approved(digest string) bool {
	return !c.NeedsApproval() || (c.ApprovedDigest != "" && c.ApprovedDigest == digest)
}

// Calibrated reports whether content digest matched this finding once.
func (c *Check) Calibrated(digest string) bool {
	return c.CalibratedDigest != "" && c.CalibratedDigest == digest
}

// Approve records actor's approval of the content digest. The author of the
// current version cannot approve it, and a check that is not intrusive
// needs no approval.
func (c *Check) Approve(actor shared.ID, digest string, now time.Time) error {
	if !c.NeedsApproval() {
		return ErrApprovalNotNeeded
	}
	if c.AuthorID != nil && *c.AuthorID == actor {
		return ErrAuthorCannotApprove
	}
	c.ApprovedDigest, c.ApprovedBy, c.ApprovedAt = digest, &actor, &now
	return nil
}

// ContentChanged resets the approval and the calibration: both belong to
// the bytes they were given for. author wrote the new version.
func (c *Check) ContentChanged(author *shared.ID) {
	c.ApprovedDigest, c.ApprovedBy, c.ApprovedAt = "", nil, nil
	c.CalibratedDigest, c.CalibratedAt = "", nil
	c.AuthorID = author
}

// Repository stores retest checks. Every method is scoped to a tenant.
type Repository interface {
	// GetByFinding returns the finding's check (shared.ErrNotFound when it
	// has none).
	GetByFinding(ctx context.Context, tenantID, findingID shared.ID) (*Check, error)
	// Upsert creates or replaces the finding's check.
	Upsert(ctx context.Context, c *Check) error
	// Delete removes the finding's check (shared.ErrNotFound when none).
	Delete(ctx context.Context, tenantID, findingID shared.ID) error
	// CountByTemplate counts the checks that use a template.
	CountByTemplate(ctx context.Context, tenantID, templateID shared.ID) (int, error)
	// MarkCalibrated records that digest matched the finding, unless the
	// check's content changed meanwhile (the template digest no longer
	// equals digest is the caller's check; this only writes).
	MarkCalibrated(ctx context.Context, tenantID, checkID shared.ID, digest string, at time.Time) error
}
