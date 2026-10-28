package tenantai

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/aimask"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The organization's AI masking policy and its preview
// (docs/architecture/ai-context-masking.md).
//
// Security model:
//   - The policy only governs internal data; restricted data and secrets are
//     always masked. The API requires an administrator, settings:write and a
//     recent sign-in for a change; a change that masks less is flagged in the
//     audit row (high severity).
//   - The preview reads the finding under the caller's own data scope and
//     pentest campaign rules, applies the AI egress policy (a refused finding
//     is never previewed), builds the real bundle with a throwaway key, and
//     returns the masked text and the placeholders with their class only.
//     The mapping is discarded; no real value is returned. Audited.

// FindingReader reads a finding under the caller's data scope
// (*finding.VulnerabilityService).
type FindingReader interface {
	GetFindingWithScope(ctx context.Context, tenantID, findingID, actingUserID string, isAdmin bool) (*vulnerability.Finding, error)
}

// AssetReader reads an asset of the tenant.
type AssetReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*assetdom.Asset, error)
}

// TenantReader reads the organization (its name is masked as ORG).
type TenantReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// MaskingService reads and changes the masking policy and previews it.
type MaskingService struct {
	repo     tenant.AIMaskingRepository
	findings FindingReader
	assets   AssetReader
	tenants  TenantReader
	bundles  *aibundle.Builder
	audit    *auditapp.AuditService
	log      *logger.Logger
	now      func() time.Time
}

// NewMaskingService builds the service. findings, assets and tenants may be
// nil: the preview is then unavailable (assets and tenants only enrich it).
func NewMaskingService(repo tenant.AIMaskingRepository, findings FindingReader, assets AssetReader, tenants TenantReader,
	bundles *aibundle.Builder, auditSvc *auditapp.AuditService, log *logger.Logger) *MaskingService {
	if log == nil {
		log = logger.NewNop()
	}
	return &MaskingService{repo: repo, findings: findings, assets: assets, tenants: tenants, bundles: bundles,
		audit: auditSvc, log: log.With("service", "ai_masking"), now: time.Now}
}

// ErrPreviewUnavailable: the server was built without a finding reader.
var ErrPreviewUnavailable = errors.New("AI masking preview is not available")

// MaskingClass is one configurable class and whether it is masked.
type MaskingClass struct {
	Class  string `json:"class"`
	Masked bool   `json:"masked"`
}

// MaskingView is the policy as the API shows it.
type MaskingView struct {
	Classes             []MaskingClass
	MaskSubdomainLabels bool
	Terms               []string
	MaxTerms            int
	UpdatedAt           *time.Time
	UpdatedBy           string
}

// MaskingUpdate replaces the policy.
type MaskingUpdate struct {
	// Off are the classes left readable in internal data.
	Off                 []string
	MaskSubdomainLabels bool
	Terms               []string
}

// MaskingPreview is what the AI would get for one finding.
type MaskingPreview struct {
	Text           string
	Placeholders   []aimask.Placeholder
	FieldsSent     []string
	FieldsWithheld []string
	DataClass      string
}

func maskingView(p tenant.AIMaskingPolicy) MaskingView {
	v := MaskingView{MaskSubdomainLabels: p.MaskSubdomainLabels, Terms: append([]string{}, p.Terms...),
		MaxTerms: aimask.MaxTerms, UpdatedAt: p.UpdatedAt, UpdatedBy: p.UpdatedBy}
	for _, c := range tenant.AIMaskClasses {
		v.Classes = append(v.Classes, MaskingClass{Class: string(c), Masked: p.Masked(c)})
	}
	return v
}

// Policy returns the organization's masking policy (for the bundle builder).
func (s *MaskingService) Policy(ctx context.Context, tenantID shared.ID) (tenant.AIMaskingPolicy, error) {
	return s.repo.GetMasking(ctx, tenantID)
}

// GetMasking returns the organization's policy.
func (s *MaskingService) GetMasking(ctx context.Context, tenantID string) (MaskingView, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return MaskingView{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	p, err := s.repo.GetMasking(ctx, tid)
	if err != nil {
		return MaskingView{}, err
	}
	return maskingView(p), nil
}

// SaveMasking replaces the organization's policy and audits the change.
func (s *MaskingService) SaveMasking(ctx context.Context, tenantID string, in MaskingUpdate, actx auditapp.AuditContext) (MaskingView, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return MaskingView{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	cur, err := s.repo.GetMasking(ctx, tid)
	if err != nil {
		return MaskingView{}, err
	}
	next := tenant.AIMaskingPolicy{MaskSubdomainLabels: in.MaskSubdomainLabels, Terms: in.Terms}
	for _, o := range in.Off {
		next.Off = append(next.Off, tenant.AIMaskClass(o))
	}
	next, err = next.Normalize()
	if err != nil {
		return MaskingView{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	next.UpdatedAt, next.UpdatedBy = &now, actx.ActorID
	if err := s.repo.SaveMasking(ctx, tid, next); err != nil {
		return MaskingView{}, err
	}
	loosens := cur.Loosens(next)
	actx.TenantID = tenantID
	msg := "The organization's AI masking policy changed"
	if loosens {
		msg = "The organization's AI masking policy changed: less is masked before AI providers see finding content"
	}
	event := auditapp.NewSuccessEvent(audit.ActionAIMaskingUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(
							map[string]any{"off": classNames(cur.Off), "mask_subdomain_labels": cur.MaskSubdomainLabels, "terms": len(cur.Terms)},
							map[string]any{"off": classNames(next.Off), "mask_subdomain_labels": next.MaskSubdomainLabels, "terms": len(next.Terms)})).
		WithMetadata("loosened", loosens). // term values are customer names: counted, never logged
		WithMessage(msg).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)
	return maskingView(next), nil
}

func classNames(cs []tenant.AIMaskClass) string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c))
	}
	return strings.Join(out, ",")
}

// PreviewInput selects the finding and the data class to preview.
type PreviewInput struct {
	TenantID  string
	FindingID string
	UserID    string
	IsAdmin   bool
	// DataClass is the ceiling to preview under; "" is internal.
	DataClass string
}

// PreviewMasking builds the bundle the AI would get for one finding, with a
// throwaway key, and returns it masked. No real value leaves this call.
func (s *MaskingService) PreviewMasking(ctx context.Context, in PreviewInput, actx auditapp.AuditContext) (MaskingPreview, error) {
	if s.findings == nil || s.bundles == nil {
		return MaskingPreview{}, ErrPreviewUnavailable
	}
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return MaskingPreview{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	ceiling := aipolicy.ClassInternal
	if in.DataClass != "" {
		c, err := aipolicy.ParseClass(in.DataClass)
		if err != nil || c == aipolicy.ClassTenantOnly {
			return MaskingPreview{}, fmt.Errorf("%w: data class is public, internal or restricted", shared.ErrValidation)
		}
		ceiling = c
	}
	// The caller's own access decides: out of scope or another
	// organization's finding is not found.
	f, err := s.findings.GetFindingWithScope(ctx, in.TenantID, in.FindingID, in.UserID, in.IsAdmin)
	if err != nil {
		return MaskingPreview{}, err
	}
	if f.TenantID() != tid {
		return MaskingPreview{}, shared.ErrNotFound
	}
	policy, err := s.repo.GetMasking(ctx, tid)
	if err != nil {
		return MaskingPreview{}, err
	}
	key := make([]byte, aimask.KeySize)
	if _, err := rand.Read(key); err != nil {
		return MaskingPreview{}, fmt.Errorf("masking key: %w", err)
	}
	bin, err := s.bundleInput(ctx, tid, f, ceiling, policy, key)
	if err != nil {
		return MaskingPreview{}, err
	}
	b, err := s.bundles.Build(ctx, bin)
	if err != nil {
		return MaskingPreview{}, err
	}
	out := MaskingPreview{Text: b.Text, Placeholders: b.Masker.Placeholders(), DataClass: string(b.DataClass)}
	for _, f := range b.FieldsSent {
		out.FieldsSent = append(out.FieldsSent, string(f))
	}
	for _, f := range b.FieldsWithheld {
		out.FieldsWithheld = append(out.FieldsWithheld, string(f))
	}
	actx.TenantID = in.TenantID
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionAIMaskingPreviewed, audit.ResourceTypeFinding, f.ID().String()).
		WithMetadata("data_class", string(ceiling)).
		WithMessage("Previewed the masked AI context of a finding").
		WithSeverity(audit.SeverityLow))
	return out, nil
}

func (s *MaskingService) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.log.Error("failed to log audit event", "error", err, "action", event.Action)
	}
}

// BundleInput assembles the bundle builder's input for a finding under the
// organization's masking policy: its asset and the organization's name as
// seeded identifiers. The preview and the built-in executor use the same
// input, so the preview shows exactly what a run sends.
func (s *MaskingService) BundleInput(ctx context.Context, tenantID shared.ID, f *vulnerability.Finding, ceiling aipolicy.Class, runKey []byte) (aibundle.Input, error) {
	policy, err := s.repo.GetMasking(ctx, tenantID)
	if err != nil {
		return aibundle.Input{}, err
	}
	return s.bundleInput(ctx, tenantID, f, ceiling, policy, runKey)
}

func (s *MaskingService) bundleInput(ctx context.Context, tid shared.ID, f *vulnerability.Finding, ceiling aipolicy.Class, policy tenant.AIMaskingPolicy, key []byte) (aibundle.Input, error) {
	bin := aibundle.Input{TenantID: tid, Finding: f, Ceiling: ceiling, Policy: policy.MaskerPolicy(), RunKey: key}
	// The organization's and the asset's names are seeded identifiers the
	// masker replaces wherever they appear. Without them the text would go out
	// with those names readable, so a failed lookup stops the run (fail closed).
	if s.tenants != nil {
		t, err := s.tenants.GetByID(ctx, tid)
		if err != nil || t == nil {
			return aibundle.Input{}, fmt.Errorf("masking: organization name unavailable: %w", errOrMissing(err))
		}
		bin.OrgNames = []string{t.Name()}
	}
	if s.assets != nil && !f.AssetID().IsZero() {
		a, err := s.assets.GetByID(ctx, tid, f.AssetID())
		if err != nil || a == nil {
			return aibundle.Input{}, fmt.Errorf("masking: asset name unavailable: %w", errOrMissing(err))
		}
		bin.Asset = &aibundle.Asset{Name: a.Name(), Type: string(a.Type()), Criticality: string(a.Criticality()),
			Exposure: string(a.Exposure()), Identifiers: []string{a.Name()}}
	}
	return bin, nil
}

func errOrMissing(err error) error {
	if err != nil {
		return err
	}
	return shared.ErrNotFound
}
