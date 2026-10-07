// Package evidence stores and serves the typed proof attached to findings
// (docs/architecture/finding-evidence.md): it normalizes and masks what a
// tool sent, encrypts the secret values apart from the masked item, lists
// the masked items, and reveals secret values to a person who may see them,
// with an audit record and a timeline entry for every reveal.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Reveal purposes, recorded with every reveal.
const (
	PurposeView     = "view"
	PurposeCopy     = "copy"
	PurposeCopyCurl = "copy_curl"
)

// ErrRevealUnavailable: the reveal cannot be recorded (no audit service, or
// the audit write failed). A reveal that is not audited is refused.
var ErrRevealUnavailable = errors.New("evidence reveal is unavailable")

// Repository is what the service needs from storage.
type Repository interface {
	evidencedom.Repository
	// FindingExists reports whether the finding belongs to the tenant.
	FindingExists(ctx context.Context, tenantID, findingID shared.ID) (bool, error)
}

// SettingsReader returns a tenant's evidence settings.
type SettingsReader interface {
	GetEvidenceSettings(ctx context.Context, tenantID string) (*tenant.EvidenceSettings, error)
}

// ActivityWriter appends a finding timeline entry.
type ActivityWriter interface {
	Create(ctx context.Context, a *vulnerability.FindingActivity) error
}

// Auditor records an audit event.
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service is the evidence application service.
type Service struct {
	repo     Repository
	enc      crypto.Encryptor
	settings SettingsReader
	activity ActivityWriter
	audit    Auditor
	log      *logger.Logger
	now      func() time.Time
	// dailyCap bounds new records per tenant per 24 h (0 = default).
	dailyCap int
}

// NewService builds the service. enc must not be nil: with a no-op
// encryptor (no APP_ENCRYPTION_KEY, development only) secrets are still kept
// apart from the item, but not encrypted.
func NewService(repo Repository, enc crypto.Encryptor, settings SettingsReader, activity ActivityWriter, audit Auditor, log *logger.Logger) *Service {
	if enc == nil {
		enc = crypto.NewNoOpEncryptor()
	}
	return &Service{repo: repo, enc: enc, settings: settings, activity: activity, audit: audit, log: log, now: time.Now}
}

// Meta describes where items came from.
type Meta struct {
	ToolName       string
	RuleID         string
	TemplateDigest string
	CapturedAt     time.Time
}

// prepare normalizes, hashes, masks and encrypts items into records.
func (s *Service) prepare(ctx context.Context, tenantID, findingID shared.ID, retestID *shared.ID, origin evidencedom.Origin,
	items []evidencedom.Item, meta Meta,
) []evidencedom.NewRecord {
	if len(items) == 0 {
		return nil
	}
	retention := s.secretRetention(ctx, tenantID)
	now := s.now()
	captured := meta.CapturedAt
	if captured.IsZero() || captured.After(now.Add(time.Minute)) {
		captured = now
	}
	out := make([]evidencedom.NewRecord, 0, len(items))
	for _, raw := range items {
		it, ok := evidencedom.Normalize(raw)
		if !ok {
			continue
		}
		toolHash := it.ContentSHA256
		it.ContentSHA256 = ""
		hash := evidencedom.Hash(it)
		masked, secrets := evidencedom.Mask(it)
		masked.ContentSHA256 = toolHash
		if masked.CapturedAt == nil {
			c := captured
			masked.CapturedAt = &c
		}
		rec := evidencedom.Record{
			ID: shared.NewID(), TenantID: tenantID, FindingID: findingID, RetestID: retestID, Origin: origin,
			Kind: masked.Kind, ToolName: truncate(meta.ToolName, 100), RuleID: truncate(meta.RuleID, 500),
			TemplateDigest: truncate(meta.TemplateDigest, 80), Item: masked, ContentSHA256: hash,
			Truncated: masked.Truncated, CapturedAt: *masked.CapturedAt,
		}
		nr := evidencedom.NewRecord{Record: rec}
		if len(secrets) > 0 {
			exp := now.Add(retention)
			nr.Record.SecretsExpireAt = &exp
			for _, sec := range secrets {
				ct, err := s.enc.EncryptString(evidencedom.SecretAAD(tenantID, rec.ID, sec.Placeholder) + sec.Value)
				if err != nil {
					// Without its ciphertext the value stays masked forever;
					// never fall back to storing it in clear.
					s.log.Warn("evidence secret not encrypted; it stays masked", "error", logger.SanitizeError(err))
					continue
				}
				nr.Secrets = append(nr.Secrets, evidencedom.StoredSecret{
					Placeholder: sec.Placeholder, Kind: sec.Kind, Ciphertext: ct, ExpiresAt: exp,
				})
			}
		}
		nr.Record.MaskedCount = len(nr.Secrets)
		nr.Record.Placeholders = make([]string, 0, len(nr.Secrets))
		for _, sec := range nr.Secrets {
			nr.Record.Placeholders = append(nr.Record.Placeholders, sec.Placeholder)
		}
		out = append(out, nr)
	}
	return out
}

// Detection is one finding's evidence from a scan report.
type Detection struct {
	Fingerprint string
	Items       []evidencedom.Item
	Meta        Meta
}

// StoreDetections stores scan-report evidence for findings matched by
// fingerprint. Best-effort: errors are logged, never returned to ingest.
func (s *Service) StoreDetections(ctx context.Context, tenantID shared.ID, dets []Detection) {
	if s == nil || len(dets) == 0 {
		return
	}
	budget, ok := s.dailyBudget(ctx, tenantID)
	if !ok {
		return
	}
	by := make(map[string][]evidencedom.NewRecord, len(dets))
	n := 0
	for _, d := range dets {
		if n >= budget {
			s.log.Warn("evidence daily cap reached; detection evidence dropped", "tenant_id", tenantID.String())
			break
		}
		items := d.Items
		if len(items) > evidencedom.MaxItemsPerReport {
			items = items[:evidencedom.MaxItemsPerReport]
		}
		recs := s.prepare(ctx, tenantID, shared.ID{}, nil, evidencedom.OriginDetection, items, d.Meta)
		if len(recs) > budget-n {
			recs = recs[:budget-n]
		}
		n += len(recs)
		by[d.Fingerprint] = append(by[d.Fingerprint], recs...)
	}
	if stored, err := s.repo.InsertForFingerprints(ctx, tenantID, by); err != nil {
		s.log.Warn("failed to store finding evidence", "error", logger.SanitizeError(err), "findings", len(by))
	} else if stored > 0 {
		s.log.Debug("stored finding evidence", "records", stored)
	}
}

// StoreRetest stores a retest attempt's evidence. Best-effort.
func (s *Service) StoreRetest(ctx context.Context, tenantID, findingID, retestID shared.ID, items []evidencedom.Item, meta Meta) {
	if s == nil || len(items) == 0 {
		return
	}
	if len(items) > evidencedom.MaxItemsPerRetest {
		items = items[:evidencedom.MaxItemsPerRetest]
	}
	budget, ok := s.dailyBudget(ctx, tenantID)
	if !ok || budget <= 0 {
		return
	}
	rid := retestID
	recs := s.prepare(ctx, tenantID, findingID, &rid, evidencedom.OriginRetest, items, meta)
	if len(recs) > budget {
		recs = recs[:budget]
	}
	if err := s.repo.InsertForFinding(ctx, tenantID, findingID, recs); err != nil {
		s.log.Warn("failed to store retest evidence", "error", logger.SanitizeError(err), "retest_id", retestID.String())
	}
}

func (s *Service) dailyBudget(ctx context.Context, tenantID shared.ID) (int, bool) {
	limit := s.dailyCap
	if limit <= 0 {
		limit = evidencedom.DefaultTenantDailyItems
	}
	n, err := s.repo.CountSince(ctx, tenantID, s.now().Add(-24*time.Hour))
	if err != nil {
		s.log.Warn("evidence quota check failed; evidence dropped", "error", logger.SanitizeError(err))
		return 0, false
	}
	return max(limit-n, 0), true
}

func (s *Service) secretRetention(ctx context.Context, tenantID shared.ID) time.Duration {
	days := tenant.DefaultEvidenceSecretRetentionDays
	if s.settings != nil {
		if es, err := s.settings.GetEvidenceSettings(ctx, tenantID.String()); err == nil && es != nil {
			days = es.EffectiveSecretRetentionDays()
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

// List returns a finding's masked evidence, newest first. A finding outside
// the tenant is ErrNotFound.
func (s *Service) List(ctx context.Context, tenantID, findingID shared.ID, retestID *shared.ID) ([]*evidencedom.Record, error) {
	if err := s.findingInTenant(ctx, tenantID, findingID); err != nil {
		return nil, err
	}
	return s.repo.List(ctx, tenantID, findingID, retestID, evidencedom.MaxListItems)
}

func (s *Service) findingInTenant(ctx context.Context, tenantID, findingID shared.ID) error {
	ok, err := s.repo.FindingExists(ctx, tenantID, findingID)
	if err != nil {
		return err
	}
	if !ok {
		return evidencedom.ErrNotFound
	}
	return nil
}

// RevealInput is one reveal request.
type RevealInput struct {
	TenantID     shared.ID
	FindingID    shared.ID
	EvidenceID   shared.ID
	Placeholders []string
	Purpose      string
	ActorID      *shared.ID
	Audit        auditapp.AuditContext
}

// Reveal returns the plaintext of the requested placeholders of one record.
// The caller has passed the permission, data-scope and step-up gates. The
// reveal is audited before anything is returned; if the audit record cannot
// be written the reveal is refused.
func (s *Service) Reveal(ctx context.Context, in RevealInput) (map[string]string, error) {
	switch in.Purpose {
	case PurposeView, PurposeCopy, PurposeCopyCurl:
	case "":
		in.Purpose = PurposeView
	default:
		return nil, fmt.Errorf("%w: purpose must be view, copy or copy_curl", shared.ErrValidation)
	}
	want, err := cleanPlaceholders(in.Placeholders)
	if err != nil {
		return nil, err
	}
	if err := s.findingInTenant(ctx, in.TenantID, in.FindingID); err != nil {
		return nil, err
	}
	rec, err := s.repo.Get(ctx, in.TenantID, in.FindingID, in.EvidenceID)
	if err != nil {
		return nil, err
	}
	if !rec.SecretsAvailable(s.now()) {
		return nil, evidencedom.ErrSecretsExpired
	}
	stored, err := s.repo.Secrets(ctx, in.TenantID, rec.ID, want)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 {
		return nil, evidencedom.ErrSecretsExpired
	}
	out := make(map[string]string, len(stored))
	for _, st := range stored {
		if !st.ExpiresAt.After(s.now()) {
			continue
		}
		plain, err := s.enc.DecryptString(st.Ciphertext)
		if err != nil {
			return nil, evidencedom.ErrSecretUnreadable
		}
		prefix := evidencedom.SecretAAD(in.TenantID, rec.ID, st.Placeholder)
		v, ok := strings.CutPrefix(plain, prefix)
		if !ok {
			return nil, evidencedom.ErrSecretUnreadable
		}
		out[st.Placeholder] = v
	}
	if len(out) == 0 {
		return nil, evidencedom.ErrSecretsExpired
	}
	revealed := make([]string, 0, len(out))
	for _, p := range want {
		if _, ok := out[p]; ok {
			revealed = append(revealed, p)
		}
	}
	if err := s.record(ctx, in, rec, revealed); err != nil {
		return nil, err
	}
	return out, nil
}

// record writes the audit event (required) and the timeline entry.
func (s *Service) record(ctx context.Context, in RevealInput, rec *evidencedom.Record, placeholders []string) error {
	if s.audit == nil {
		return ErrRevealUnavailable
	}
	in.Audit.TenantID = in.TenantID.String()
	event := auditapp.NewSuccessEvent(auditdom.ActionFindingEvidenceRevealed, auditdom.ResourceTypeFinding, in.FindingID.String()).
		WithResourceName(in.FindingID.String()).
		WithMessage(fmt.Sprintf("Revealed %d masked value(s) of finding evidence (%s)", len(placeholders), in.Purpose)).
		WithMetadata("evidence_id", rec.ID.String()).
		WithMetadata("kind", rec.Kind).
		WithMetadata("placeholders", placeholders).
		WithMetadata("purpose", in.Purpose).
		WithSeverity(auditdom.SeverityHigh)
	if err := s.audit.LogEvent(ctx, in.Audit, event); err != nil {
		s.log.Error("evidence reveal refused: audit not recorded", "error", logger.SanitizeError(err))
		return ErrRevealUnavailable
	}
	if s.activity == nil {
		return nil
	}
	a, err := vulnerability.NewFindingActivity(in.TenantID, in.FindingID, vulnerability.ActivityEvidenceRevealed,
		in.ActorID, vulnerability.ActorTypeUser, map[string]interface{}{
			"evidence_id":  rec.ID.String(),
			"kind":         rec.Kind,
			"placeholders": placeholders,
			"purpose":      in.Purpose,
		}, vulnerability.SourceAPI, nil)
	if err == nil {
		err = s.activity.Create(ctx, a)
	}
	if err != nil {
		// The audit record exists; the timeline entry is best-effort.
		s.log.Warn("evidence reveal: timeline entry not written", "error", logger.SanitizeError(err))
	}
	return nil
}

func cleanPlaceholders(ps []string) ([]string, error) {
	if len(ps) == 0 {
		return nil, fmt.Errorf("%w: placeholders are required", shared.ErrValidation)
	}
	if len(ps) > evidencedom.MaxRevealPlaceholders {
		return nil, fmt.Errorf("%w: at most %d placeholders per reveal", shared.ErrValidation, evidencedom.MaxRevealPlaceholders)
	}
	seen := make(map[string]bool, len(ps))
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if !evidencedom.IsPlaceholder(p) {
			return nil, fmt.Errorf("%w: invalid placeholder", shared.ErrValidation)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// Sweep deletes expired secrets and records past the retention.
func (s *Service) Sweep(ctx context.Context) error {
	secrets, records, err := s.repo.DeleteExpired(ctx, s.now(), time.Duration(evidencedom.RetentionDays)*24*time.Hour)
	if err != nil {
		return err
	}
	if secrets > 0 || records > 0 {
		s.log.Info("evidence retention sweep", "secrets_deleted", secrets, "records_deleted", records)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
