// Package retestcheck manages a finding's retest check: the custom check a
// person attaches to a finding so that its retest re-runs it.
// Design and threat model: docs/architecture/finding-retest-checks.md.
//
// The check's content lives in the organization's template library (one
// content system: versioned by content digest, approved for sensors as the
// organization's policy says, signed on delivery). This package adds the
// rules a check must pass (rules.go), approval of intrusive checks by a
// second person, and calibration: a check proves a fix only after the same
// version matched the finding once.
package retestcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/retestcheck"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// templateTag marks the library templates created for a retest check.
const templateTag = "retest-check"

// Errors.
var (
	// ErrInvalid: the check does not pass validation (the message lists why).
	ErrInvalid = shared.NewDomainError("RETEST_CHECK_INVALID", "the retest check is not valid", shared.ErrValidation)
	// ErrNotRunnable: a check exists but cannot run now (the message says
	// why); it wraps shared.ErrValidation so a retest is refused.
	ErrNotRunnable = errors.New("the finding's retest check cannot run")
)

// FindingReader reads one finding of a tenant.
type FindingReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// TemplateStore is the template library (an adapter over the scanner
// template service, so creating and editing a check's template goes
// through the same validation, quota and approval for sensors as any
// upload). Every method is tenant-scoped.
type TemplateStore interface {
	Get(ctx context.Context, tenantID, templateID shared.ID) (*scannertemplate.ScannerTemplate, error)
	Create(ctx context.Context, tenantID, userID shared.ID, name string, content []byte, tags []string) (*scannertemplate.ScannerTemplate, error)
	UpdateContent(ctx context.Context, tenantID, templateID, userID shared.ID, content []byte) (*scannertemplate.ScannerTemplate, error)
	Delete(ctx context.Context, tenantID, templateID shared.ID) error
}

// AuditLogger writes audit events.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service manages retest checks.
type Service struct {
	repo      dom.Repository
	findings  FindingReader
	templates TemplateStore
	audit     AuditLogger
	now       func() time.Time
	logger    *logger.Logger
}

// NewService wires the service.
func NewService(repo dom.Repository, findings FindingReader, templates TemplateStore, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, findings: findings, templates: templates, audit: audit, now: time.Now,
		logger: log.With("service", "retest_check")}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Input is what a person submits: a nuclei template (Content), a declarative
// assertion, or a library template to reuse (TemplateID).
type Input struct {
	Kind       dom.Kind
	Name       string
	Content    string
	Assertion  *dom.HTTPAssertion
	TemplateID string
}

// Validation is the outcome of validating an Input.
type Validation struct {
	Valid            bool
	Issues           []dom.Issue
	Tier             string
	TierReason       string
	Capabilities     []string
	Content          string
	ApprovalRequired bool
	// resolved state for Save.
	content  []byte
	analysis *Analysis
	library  *scannertemplate.ScannerTemplate
}

// View is a check with its template.
type View struct {
	Check    *dom.Check
	Template *scannertemplate.ScannerTemplate
}

// Digest is the check's current content digest.
func (v *View) Digest() string { return v.Template.ContentDigest() }

// Get returns the finding's check (nil when it has none).
func (s *Service) Get(ctx context.Context, tenantID, findingID shared.ID) (*View, error) {
	if _, err := s.findings.GetByID(ctx, tenantID, findingID); err != nil {
		return nil, err
	}
	c, err := s.repo.GetByFinding(ctx, tenantID, findingID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t, err := s.templates.Get(ctx, tenantID, c.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("read the check's template: %w", err)
	}
	return &View{Check: c, Template: t}, nil
}

// Validate checks an input without saving anything.
func (s *Service) Validate(ctx context.Context, tenantID, findingID shared.ID, in Input) (*Validation, error) {
	if _, err := s.findings.GetByID(ctx, tenantID, findingID); err != nil {
		return nil, err
	}
	return s.validate(ctx, tenantID, findingID, in)
}

func (s *Service) validate(ctx context.Context, tenantID, findingID shared.ID, in Input) (*Validation, error) {
	v := &Validation{}
	fail := func(field, code, msg string) (*Validation, error) {
		v.Issues = append(v.Issues, dom.Issue{Field: field, Code: code, Message: msg})
		return v, nil
	}
	if len(in.Name) > 200 {
		return fail("name", "NAME", "the name is longer than 200 characters")
	}
	switch {
	case !in.Kind.Valid():
		return fail("kind", "KIND", "kind must be nuclei or http_assertion")
	case in.Kind == dom.KindHTTPAssertion:
		if in.Assertion == nil || in.Content != "" || in.TemplateID != "" {
			return fail("assertion", "ASSERTION", "an http_assertion check takes an assertion only")
		}
		if issues := in.Assertion.Validate(); len(issues) > 0 {
			// Fields are named from the request body ("assertion.path").
			for i := range issues {
				issues[i].Field = "assertion." + issues[i].Field
			}
			v.Issues = issues
			return v, nil
		}
		content, err := in.Assertion.Compile(findingID.String())
		if err != nil {
			return fail("assertion", "ASSERTION", err.Error())
		}
		v.content = content
	case in.TemplateID != "":
		if in.Content != "" || in.Assertion != nil {
			return fail("template_id", "TEMPLATE", "a library template is reused as it is; send no content")
		}
		id, err := shared.IDFromString(in.TemplateID)
		if err != nil {
			return fail("template_id", "TEMPLATE", "invalid template id")
		}
		t, err := s.templates.Get(ctx, tenantID, id)
		if errors.Is(err, shared.ErrNotFound) {
			return fail("template_id", "TEMPLATE", "no such template in this organization")
		}
		if err != nil {
			return nil, err
		}
		if t.TemplateType != scannertemplate.TemplateTypeNuclei || !t.Status.IsUsable() {
			return fail("template_id", "TEMPLATE", "only an active nuclei template can be a retest check")
		}
		v.content, v.library = t.Content, t
	default:
		if in.Assertion != nil || strings.TrimSpace(in.Content) == "" {
			return fail("content", "CONTENT", "a nuclei check takes the template content")
		}
		v.content = []byte(in.Content)
	}
	a := AnalyzeTemplate(ctx, v.content)
	v.analysis = a
	v.Issues = append(v.Issues, a.Issues...)
	if a.Valid() && a.NucleiID == "" {
		v.Issues = append(v.Issues, dom.Issue{Field: "id", Code: "ID", Message: "the template has no id"})
	}
	v.Tier, v.TierReason, v.Capabilities = a.Tier, a.TierReason, a.Capabilities
	v.Content = string(v.content)
	v.ApprovalRequired = a.Tier == dom.TierT2
	v.Valid = len(v.Issues) == 0
	return v, nil
}

// Save attaches or replaces the finding's check, written by actor.
func (s *Service) Save(ctx context.Context, actx auditapp.AuditContext, tenantID, findingID, actor shared.ID, in Input) (*View, error) {
	if _, err := s.findings.GetByID(ctx, tenantID, findingID); err != nil {
		return nil, err
	}
	val, err := s.validate(ctx, tenantID, findingID, in)
	if err != nil {
		return nil, err
	}
	if !val.Valid {
		return nil, invalid(val.Issues)
	}
	prev, err := s.repo.GetByFinding(ctx, tenantID, findingID)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	var prevDigest string
	var prevTemplate *scannertemplate.ScannerTemplate
	if prev != nil {
		if prevTemplate, err = s.templates.Get(ctx, tenantID, prev.TemplateID); err == nil {
			prevDigest = prevTemplate.ContentDigest()
		}
	}

	now := s.now().UTC()
	c := prev
	if c == nil {
		c = &dom.Check{ID: shared.NewID(), TenantID: tenantID, FindingID: findingID, CreatedBy: &actor, CreatedAt: now}
	}
	var tmpl *scannertemplate.ScannerTemplate
	var orphan *shared.ID // a template the check owned and no longer uses
	switch {
	case val.library != nil:
		tmpl = val.library
		if prev != nil && prev.OwnsTemplate && prev.TemplateID != tmpl.ID {
			id := prev.TemplateID
			orphan = &id
		}
		c.OwnsTemplate = false
	case prev != nil && prev.OwnsTemplate && prevTemplate != nil:
		tmpl = prevTemplate
		if prevDigest != "sha256:"+sha256Hex(val.content) {
			if tmpl, err = s.templates.UpdateContent(ctx, tenantID, prev.TemplateID, actor, val.content); err != nil {
				return nil, err
			}
		}
	default:
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = dom.TemplateIDFor(findingID.String())
		}
		if tmpl, err = s.templates.Create(ctx, tenantID, actor, name, val.content, []string{templateTag}); err != nil {
			return nil, err
		}
		c.OwnsTemplate = true
	}
	c.TemplateID = tmpl.ID
	c.Kind = in.Kind
	if val.library != nil {
		c.Kind = dom.KindNuclei
	}
	c.Assertion = nil
	if c.Kind == dom.KindHTTPAssertion {
		c.Assertion = in.Assertion
	}
	c.Tier, c.TierReason = val.Tier, val.TierReason
	if tmpl.ContentDigest() != prevDigest {
		c.ContentChanged(&actor)
	}
	c.UpdatedBy, c.UpdatedAt = &actor, now
	if err := s.repo.Upsert(ctx, c); err != nil {
		return nil, err
	}
	if orphan != nil {
		s.dropOwnedTemplate(ctx, tenantID, *orphan)
	}
	s.auditEvent(ctx, actx, auditdom.ActionFindingRetestCheckSaved, c, tmpl, "Retest check saved")
	s.logger.Info("retest check saved", "tenant_id", tenantID.String(), "finding_id", findingID.String(),
		"template_id", tmpl.ID.String(), "digest", tmpl.ContentDigest(), "tier", c.Tier)
	return &View{Check: c, Template: tmpl}, nil
}

// Remove detaches the finding's check. A template created for it is
// deleted when no other check uses it; a library template stays.
func (s *Service) Remove(ctx context.Context, actx auditapp.AuditContext, tenantID, findingID shared.ID) error {
	v, err := s.Get(ctx, tenantID, findingID)
	if err != nil {
		return err
	}
	if v == nil {
		return fmt.Errorf("%w: the finding has no retest check", shared.ErrNotFound)
	}
	if err := s.repo.Delete(ctx, tenantID, findingID); err != nil {
		return err
	}
	if v.Check.OwnsTemplate {
		s.dropOwnedTemplate(ctx, tenantID, v.Check.TemplateID)
	}
	s.auditEvent(ctx, actx, auditdom.ActionFindingRetestCheckRemoved, v.Check, v.Template, "Retest check removed")
	return nil
}

// Approve records actor's approval of the check's current version (an
// intrusive check runs only once a second person approved it).
func (s *Service) Approve(ctx context.Context, actx auditapp.AuditContext, tenantID, findingID, actor shared.ID) (*View, error) {
	v, err := s.Get(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("%w: the finding has no retest check", shared.ErrNotFound)
	}
	if v.Check.Approved(v.Digest()) && v.Check.NeedsApproval() {
		return v, nil
	}
	// Neither the person who attached this version nor the author of the
	// template's content approves it.
	if a := v.Template.ContentAuthorID; a != nil && *a == actor && v.Check.NeedsApproval() {
		return nil, dom.ErrAuthorCannotApprove
	}
	if err := v.Check.Approve(actor, v.Digest(), s.now().UTC()); err != nil {
		return nil, err
	}
	if err := s.repo.Upsert(ctx, v.Check); err != nil {
		return nil, err
	}
	s.auditEvent(ctx, actx, auditdom.ActionFindingRetestCheckApproved, v.Check, v.Template, "Retest check approved")
	return v, nil
}

// Runnable is a check ready to be sent with a retest.
type Runnable struct {
	CheckID      shared.ID
	TemplateID   shared.ID
	TemplateName string
	// NucleiID is the template's id: the retest item's rule id.
	NucleiID string
	Content  []byte
	Digest   string
	// Path is the first request's path on the target: the endpoint the
	// re-run must prove it requested.
	Path string
}

// RunnableCheck returns the finding's check when it can run now, (nil, nil)
// when the finding has none, or an error wrapping ErrNotRunnable (and
// shared.ErrValidation) that says why it cannot. The content is checked
// again with today's rules: a check never runs on an earlier verdict.
func (s *Service) RunnableCheck(ctx context.Context, tenantID, findingID shared.ID) (*Runnable, error) {
	c, err := s.repo.GetByFinding(ctx, tenantID, findingID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t, err := s.templates.Get(ctx, tenantID, c.TemplateID)
	if err != nil {
		return nil, notRunnable("its template cannot be read")
	}
	if t.TemplateType != scannertemplate.TemplateTypeNuclei || !t.Status.IsUsable() {
		return nil, notRunnable("its template is not an active nuclei template")
	}
	a := AnalyzeTemplate(ctx, t.Content)
	if !a.Valid() || a.NucleiID == "" {
		return nil, notRunnable("its template no longer passes validation")
	}
	digest := t.ContentDigest()
	c.Tier = a.Tier
	if !c.Approved(digest) {
		return nil, notRunnable("it is intrusive and its current version is not approved by a second person")
	}
	if !t.ApprovedForSensors() {
		return nil, notRunnable("its template version awaits approval for sensors")
	}
	return &Runnable{CheckID: c.ID, TemplateID: t.ID, TemplateName: t.Name, NucleiID: a.NucleiID,
		Content: t.Content, Digest: digest, Path: a.FirstPath}, nil
}

// CalibratedDigest is the digest that matched the check's finding once ("" when
// none, or the check is gone).
func (s *Service) CalibratedDigest(ctx context.Context, tenantID, findingID, checkID shared.ID) (string, error) {
	c, err := s.repo.GetByFinding(ctx, tenantID, findingID)
	if errors.Is(err, shared.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if c.ID != checkID {
		return "", nil
	}
	return c.CalibratedDigest, nil
}

// MarkCalibrated records that digest matched the check's finding.
func (s *Service) MarkCalibrated(ctx context.Context, tenantID, checkID shared.ID, digest string) error {
	return s.repo.MarkCalibrated(ctx, tenantID, checkID, digest, s.now().UTC())
}

func (s *Service) dropOwnedTemplate(ctx context.Context, tenantID, templateID shared.ID) {
	n, err := s.repo.CountByTemplate(ctx, tenantID, templateID)
	if err != nil || n > 0 {
		return
	}
	if err := s.templates.Delete(ctx, tenantID, templateID); err != nil {
		s.logger.Warn("retest check template not deleted", "template_id", templateID.String(), "error", err)
	}
}

func (s *Service) auditEvent(ctx context.Context, actx auditapp.AuditContext, action auditdom.Action,
	c *dom.Check, t *scannertemplate.ScannerTemplate, msg string,
) {
	if s.audit == nil {
		return
	}
	actx.TenantID = c.TenantID.String()
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeFinding, c.FindingID.String()).
		WithMessage(msg).
		WithMetadata("retest_check_id", c.ID.String()).
		WithMetadata("template_id", t.ID.String()).
		WithMetadata("template_name", t.Name).
		WithMetadata("digest", t.ContentDigest()).
		WithMetadata("kind", string(c.Kind)).
		WithMetadata("tier", c.Tier)
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit retest check", "finding_id", c.FindingID.String(), "error", err)
	}
}

func notRunnable(why string) error {
	return fmt.Errorf("%w: %w: %s", shared.ErrValidation, ErrNotRunnable, why)
}

func invalid(issues []dom.Issue) error {
	msgs := make([]string, 0, len(issues))
	for _, i := range issues {
		msgs = append(msgs, i.Field+": "+i.Message)
	}
	return &shared.DomainError{Code: ErrInvalid.Code, Message: ErrInvalid.Message + ": " + strings.Join(msgs, "; "), Err: ErrInvalid.Err}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
