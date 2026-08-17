// Package exposurebridge promotes internal findings that represent an EXPOSURE
// rather than a code vulnerability into the Exposure Register (the exposure
// event store), so they show up in the Exposures view continuously — realizing
// the CTEM Discovery "exposure ≠ vulnerability" principle. Two projections:
//
//   - secret-scan findings (gitleaks, trufflehog, ...) → credential_leaked
//     events, so a hardcoded secret is tracked continuously, not only when a
//     breach dump is manually imported;
//   - misconfiguration findings (IaC/CSPM: Checkov, Tfsec, cloud posture) →
//     misconfiguration events.
//
// Both are typed projections over existing findings that reuse the exposure
// domain + repository and mirror the dedupe/reactivate behavior of the
// credential-import service — NOT a separate event table.
//
// The provenance is labeled distinctly: these events carry
// discovery_source="secret_scan" and source="secret_scan", which is NOT the
// same as an externally-leaked credential imported from a breach feed (those
// keep their import source string). An in-repo hardcoded secret and an
// externally-leaked credential are both credential_leaked events, but the
// discovery channel is preserved so the UI/reporting can tell them apart.
//
// It reuses the exposure domain + repository and mirrors the dedupe/reactivate
// behavior of the credential-import service (see
// internal/app/integration/credential_import.go): a re-scan finding the same
// secret updates the existing event's last_seen (reactivating it if it was
// resolved) instead of creating a duplicate. The raw secret value is never
// persisted — only the finding's already-masked value is carried.
package exposurebridge

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// SourceSecretScan is the provenance label carried on both the exposure event
// source column and the discovery_source detail. It marks the event as an
// INTERNAL secret-scan discovery, distinct from an external breach import.
const SourceSecretScan = "secret_scan"

// SourceMisconfigScan is the provenance label for exposures projected from
// misconfiguration findings (IaC/CSPM: Checkov, Tfsec, Trivy config, cloud
// posture). A misconfiguration is an exposure that is NOT a CVE — the CTEM
// Discovery "exposure ≠ vulnerability" principle — so it belongs in the
// Exposure Register alongside leaked credentials.
const SourceMisconfigScan = "misconfig_scan"

// discoverySourceKey is the detail key holding the provenance label so the
// UI/reporting can distinguish secret-scan discoveries from breach imports.
const discoverySourceKey = "discovery_source"

// Bridge promotes secret-scan findings into exposure events. It is best-effort:
// a failure here must never fail finding ingest.
type Bridge struct {
	exposureRepo exposure.Repository
	historyRepo  exposure.StateHistoryRepository
	logger       *logger.Logger
}

// NewBridge creates a Bridge. historyRepo may be nil (state-change history is
// then simply not recorded).
func NewBridge(
	exposureRepo exposure.Repository,
	historyRepo exposure.StateHistoryRepository,
	log *logger.Logger,
) *Bridge {
	return &Bridge{
		exposureRepo: exposureRepo,
		historyRepo:  historyRepo,
		logger:       log.With("service", "exposure_bridge"),
	}
}

// ApplyBatch bridges every secret-scan and misconfiguration finding in the
// batch into the exposure store as first-class Exposure Register rows. Findings
// that are neither are ignored. Per-finding failures are logged and skipped; the
// method never returns an error so it cannot abort ingest.
func (b *Bridge) ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error {
	if b == nil || b.exposureRepo == nil {
		return nil
	}

	var bridged, failed int
	for _, f := range findings {
		if f == nil {
			continue
		}
		var (
			event *exposure.ExposureEvent
			err   error
		)
		switch {
		case isSecretFinding(f):
			event, err = b.buildEvent(tenantID, f)
		case isMisconfigFinding(f):
			event, err = b.buildMisconfigEvent(tenantID, f)
		default:
			continue
		}
		if err == nil {
			err = b.applyEvent(ctx, event, f)
		}
		if err != nil {
			failed++
			b.logger.Warn("failed to bridge finding into exposure store",
				"tenant_id", tenantID.String(),
				"finding_id", f.ID().String(),
				"error", err,
			)
			continue
		}
		bridged++
	}

	if bridged > 0 || failed > 0 {
		b.logger.Info("bridged secret-scan findings into exposure store",
			"tenant_id", tenantID.String(),
			"bridged", bridged,
			"failed", failed,
		)
	}
	return nil
}

// isSecretFinding reports whether a finding originates from a hardcoded/secret
// scan. It matches on either the source enum (gitleaks/trufflehog map to
// FindingSourceSecret) or the finding-type discriminator, so a secret finding
// is caught even if only one of the two is set.
func isSecretFinding(f *vulnerability.Finding) bool {
	return f.Source() == vulnerability.FindingSourceSecret ||
		f.FindingType() == vulnerability.FindingTypeSecret
}

// isMisconfigFinding reports whether a finding is a misconfiguration (IaC or
// cloud posture). It matches on either the finding-type discriminator or the
// source enum (IaC scanners and CSPM tools), so a misconfiguration is caught
// even if only one of the two is set. Secret findings are excluded by the
// caller's switch ordering (secret is checked first).
func isMisconfigFinding(f *vulnerability.Finding) bool {
	return f.FindingType() == vulnerability.FindingTypeMisconfiguration ||
		f.Source() == vulnerability.FindingSourceIaC ||
		f.Source() == vulnerability.FindingSourceCSPM
}

// applyEvent upserts a single prebuilt exposure event into the store, mirroring
// the credential-import dedupe/reactivate semantics: a re-scan finding the same
// exposure updates last_seen (reactivating a resolved one) instead of creating
// a duplicate.
func (b *Bridge) applyEvent(ctx context.Context, event *exposure.ExposureEvent, f *vulnerability.Finding) error {
	existing, err := b.exposureRepo.GetByFingerprint(ctx, event.TenantID(), event.Fingerprint())
	if err != nil && !exposure.IsExposureEventNotFound(err) {
		return fmt.Errorf("failed to check existing exposure: %w", err)
	}

	if existing == nil {
		if err := b.exposureRepo.Create(ctx, event); err != nil {
			// A concurrent bridge for the same exposure may have won the race.
			// Treat an existing fingerprint as success (idempotent).
			if exposure.IsExposureEventExists(err) {
				return nil
			}
			return fmt.Errorf("failed to create exposure event: %w", err)
		}
		return nil
	}

	return b.reconcileExisting(ctx, existing, f)
}

// buildEvent constructs the exposure event for a secret finding. The dedupe
// fingerprint is derived by the entity from tenant/event_type/title/source/
// asset plus the whitelisted "service" and "path" details — a stable natural
// key that repeats across re-scans of the same secret. Non-whitelisted details
// (finding_id, masked_value, ...) can change without breaking dedupe.
func (b *Bridge) buildEvent(tenantID shared.ID, f *vulnerability.Finding) (*exposure.ExposureEvent, error) {
	details := map[string]any{
		discoverySourceKey:    SourceSecretScan,
		"finding_id":          f.ID().String(),
		"finding_fingerprint": f.Fingerprint(),
	}
	if st := f.SecretType(); st != "" {
		details["secret_type"] = st
	}
	if svc := f.SecretService(); svc != "" {
		details["service"] = svc // whitelisted → contributes to dedupe fingerprint
	}
	if path := f.FilePath(); path != "" {
		details["path"] = path // whitelisted → contributes to dedupe fingerprint
	}
	// SECURITY: only the finding's already-masked value is carried. The raw
	// secret is never available here (the ingest processor redacts it).
	if mv := f.SecretMaskedValue(); mv != "" {
		details["masked_value"] = mv
	}
	if rid := f.RuleID(); rid != "" {
		details["rule_id"] = rid
	}

	sev, err := exposure.ParseSeverity(f.Severity().String())
	if err != nil {
		sev = exposure.SeverityMedium
	}

	event, err := exposure.NewExposureEvent(
		tenantID,
		exposure.EventTypeCredentialLeaked,
		sev,
		secretTitle(f),
		SourceSecretScan,
		details,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build exposure event: %w", err)
	}

	// Link back to the source asset. SetAssetID recomputes the fingerprint so
	// it embeds the asset — call it before reading event.Fingerprint().
	if aid := f.AssetID(); !aid.IsZero() {
		event.SetAssetID(&aid)
	}

	event.UpdateDescription("Hardcoded secret discovered by internal secret scan")

	return event, nil
}

// secretTitle picks a stable, human-readable title for the exposure event.
func secretTitle(f *vulnerability.Finding) string {
	if t := f.Title(); t != "" {
		return t
	}
	if rn := f.RuleName(); rn != "" {
		return rn
	}
	if st := f.SecretType(); st != "" {
		return "Hardcoded secret: " + st
	}
	return "Hardcoded secret"
}

// buildMisconfigEvent constructs the exposure event for a misconfiguration
// finding. Dedupe is by tenant/event_type/title/source/asset plus the
// whitelisted "path" detail (the IaC resource path), so re-scans of the same
// misconfigured resource fold onto one Exposure Register row instead of
// duplicating. Non-whitelisted details (policy id, expected/actual, ...) may
// change without breaking dedupe.
func (b *Bridge) buildMisconfigEvent(tenantID shared.ID, f *vulnerability.Finding) (*exposure.ExposureEvent, error) {
	details := map[string]any{
		discoverySourceKey:    SourceMisconfigScan,
		"finding_id":          f.ID().String(),
		"finding_fingerprint": f.Fingerprint(),
	}
	if pid := f.MisconfigPolicyID(); pid != "" {
		details["policy_id"] = pid
	}
	if pn := f.MisconfigPolicyName(); pn != "" {
		details["policy_name"] = pn
	}
	if rt := f.MisconfigResourceType(); rt != "" {
		details["resource_type"] = rt
	}
	if rn := f.MisconfigResourceName(); rn != "" {
		details["resource_name"] = rn
	}
	if exp := f.MisconfigExpected(); exp != "" {
		details["expected"] = exp
	}
	if act := f.MisconfigActual(); act != "" {
		details["actual"] = act
	}
	if rid := f.RuleID(); rid != "" {
		details["rule_id"] = rid
	}
	// The resource path (or file path) is the stable natural key for a
	// misconfiguration; whitelist it into the dedupe fingerprint via "path".
	if rp := f.MisconfigResourcePath(); rp != "" {
		details["path"] = rp
	} else if fp := f.FilePath(); fp != "" {
		details["path"] = fp
	}

	sev, err := exposure.ParseSeverity(f.Severity().String())
	if err != nil {
		sev = exposure.SeverityMedium
	}

	event, err := exposure.NewExposureEvent(
		tenantID,
		exposure.EventTypeMisconfiguration,
		sev,
		misconfigTitle(f),
		SourceMisconfigScan,
		details,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build misconfiguration exposure event: %w", err)
	}

	// Link back to the source asset. SetAssetID recomputes the fingerprint so it
	// embeds the asset — call it before reading event.Fingerprint().
	if aid := f.AssetID(); !aid.IsZero() {
		event.SetAssetID(&aid)
	}

	if desc := f.MisconfigCause(); desc != "" {
		event.UpdateDescription(desc)
	} else {
		event.UpdateDescription("Misconfiguration discovered by infrastructure/cloud posture scan")
	}

	return event, nil
}

// misconfigTitle picks a stable, human-readable title for a misconfiguration
// exposure. A stable title matters: it is part of the dedupe fingerprint.
func misconfigTitle(f *vulnerability.Finding) string {
	if t := f.Title(); t != "" {
		return t
	}
	if pn := f.MisconfigPolicyName(); pn != "" {
		return pn
	}
	if pid := f.MisconfigPolicyID(); pid != "" {
		return "Misconfiguration: " + pid
	}
	return "Misconfiguration"
}

// reconcileExisting mirrors the credential-import handling of an already-known
// exposure: skip if the user marked it a false positive, reactivate + mark seen
// if it was resolved (the secret is back), otherwise just bump last_seen.
func (b *Bridge) reconcileExisting(ctx context.Context, existing *exposure.ExposureEvent, f *vulnerability.Finding) error {
	switch existing.State() {
	case exposure.StateFalsePositive:
		// Respect the user's decision — do not resurrect.
		return nil

	case exposure.StateResolved:
		previousState := existing.State()
		if err := existing.Reactivate(); err != nil {
			return fmt.Errorf("failed to reactivate exposure: %w", err)
		}
		existing.MarkSeen()
		if err := b.exposureRepo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update exposure: %w", err)
		}
		if b.historyRepo != nil {
			history, herr := exposure.NewStateHistory(
				existing.ID(),
				previousState,
				exposure.StateActive,
				nil,
				fmt.Sprintf("Reactivated by re-scan (finding: %s)", f.ID().String()),
			)
			if herr == nil {
				_ = b.historyRepo.Create(ctx, history)
			}
		}
		return nil

	default: // active, accepted
		existing.MarkSeen()
		if err := b.exposureRepo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update exposure: %w", err)
		}
		return nil
	}
}
