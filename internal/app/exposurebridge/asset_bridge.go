package exposurebridge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SourceReconScan is the provenance label carried on both the exposure event
// source column and the discovery_source detail for exposures projected from
// recon-discovered assets (open ports, exposed services, TLS certificates). It
// marks the event as an INTERNAL attack-surface discovery, distinct from a
// manual bulk-ingest of exposures or an external breach import.
const SourceReconScan = "recon_scan"

// certificateExpiryWindow is how far in the future a certificate's not_after may
// be before it is treated as "expiring" (an actionable exposure) rather than
// simply present.
const certificateExpiryWindow = 30 * 24 * time.Hour

// minRSAKeyBits is the floor below which an RSA public key is treated as weak.
const minRSAKeyBits = 2048

// AssetBridge projects recon-discovered ASSETS (open ports, exposed services,
// TLS certificates) into the Exposure Register as first-class exposure events,
// realizing the CTEM Discovery "exposure ≠ vulnerability" principle for the
// attack-surface facts that today land only as assets. It mirrors the
// finding-side Bridge: typed projections over existing signals, reusing the
// exposure domain + repository and the shared dedupe/reactivate helper — NOT a
// separate event table.
//
// The event types it emits (port_open, service_detected, certificate_expiring,
// certificate_expired, ssl_issue) were defined in the exposure vocabulary but
// had no producer until now. It is best-effort: a failure here must never fail
// asset ingest.
type AssetBridge struct {
	exposureRepo exposure.Repository
	historyRepo  exposure.StateHistoryRepository
	logger       *logger.Logger
}

// NewAssetBridge creates an AssetBridge. historyRepo may be nil (state-change
// history is then simply not recorded).
func NewAssetBridge(
	exposureRepo exposure.Repository,
	historyRepo exposure.StateHistoryRepository,
	log *logger.Logger,
) *AssetBridge {
	return &AssetBridge{
		exposureRepo: exposureRepo,
		historyRepo:  historyRepo,
		logger:       log.With("service", "exposure_asset_bridge"),
	}
}

// ProjectAssets bridges every open-port / service / certificate asset in the
// batch into the exposure store. Assets of other types are ignored. Per-asset
// failures are logged and skipped; the method never returns an error so it
// cannot abort ingest. Tenant is taken from each asset (asset.TenantID()),
// never from a caller-supplied report.
func (b *AssetBridge) ProjectAssets(ctx context.Context, tenantID shared.ID, assets []*asset.Asset) error {
	if b == nil || b.exposureRepo == nil {
		return nil
	}

	var projected, failed int
	for _, a := range assets {
		if a == nil {
			continue
		}
		// Tenant integrity: use the asset's own tenant and skip anything that
		// does not match the ingest tenant (defense-in-depth against a
		// cross-tenant asset slipping into the batch).
		if a.TenantID().IsZero() || a.TenantID() != tenantID {
			continue
		}

		events := b.buildEventsForAsset(a)
		for _, ev := range events {
			if err := upsertExposureEvent(ctx, b.exposureRepo, b.historyRepo, b.logger, ev,
				fmt.Sprintf("asset: %s", a.ID().String())); err != nil {
				failed++
				b.logger.Warn("failed to project asset into exposure store",
					"tenant_id", tenantID.String(),
					"asset_id", a.ID().String(),
					"event_type", ev.EventType().String(),
					"error", err,
				)
				continue
			}
			projected++
		}
	}

	if projected > 0 || failed > 0 {
		b.logger.Info("projected recon assets into exposure store",
			"tenant_id", tenantID.String(),
			"projected", projected,
			"failed", failed,
		)
	}
	return nil
}

// buildEventsForAsset dispatches an asset to the right exposure projection(s).
// A single asset can yield more than one event (e.g. a certificate that is both
// self-signed AND expiring). Returns nil for asset types with no clean mapping.
func (b *AssetBridge) buildEventsForAsset(a *asset.Asset) []*exposure.ExposureEvent {
	switch a.Type() {
	case asset.AssetTypeService:
		// Recon collapses open_port / http_service into the service core type
		// via TypeAliases, distinguished by sub_type.
		if a.SubType() == "open_port" {
			if ev := b.buildPortEvent(a); ev != nil {
				return []*exposure.ExposureEvent{ev}
			}
			return nil
		}
		if ev := b.buildServiceEvent(a); ev != nil {
			return []*exposure.ExposureEvent{ev}
		}
		return nil
	case asset.AssetTypeCertificate:
		return b.buildCertificateEvents(a)
	default:
		return nil
	}
}

// buildPortEvent projects an open-port asset (sub_type "open_port", flat
// port/protocol/service properties from Naabu) into a port_open exposure. The
// whitelisted port/protocol/service details make the dedupe fingerprint stable
// per (asset, port, protocol) across re-scans.
func (b *AssetBridge) buildPortEvent(a *asset.Asset) *exposure.ExposureEvent {
	props := a.Properties()
	port := propInt(props, "port")
	if port <= 0 {
		return nil // no port → nothing meaningful to track
	}
	protocol := propString(props, "protocol")
	if protocol == "" {
		protocol = "tcp"
	}
	service := propString(props, "service")

	title := fmt.Sprintf("Open port %d/%s", port, protocol)
	if service != "" {
		title = fmt.Sprintf("%s (%s)", title, service)
	}

	details := map[string]any{
		discoverySourceKey: SourceReconScan,
		"port":             port,     // whitelisted → dedupe key
		"protocol":         protocol, // whitelisted → dedupe key
	}
	if service != "" {
		details["service"] = service // whitelisted → dedupe key
	}
	if v := propString(props, "version"); v != "" {
		details["version"] = v
	}
	if h := propString(props, "host"); h != "" {
		details["host"] = h
	}

	return b.newEvent(a, exposure.EventTypePortOpen, exposure.SeverityInfo, title, details,
		"Open network port discovered by recon scan")
}

// buildServiceEvent projects a service / http_service asset into a
// service_detected exposure. Service technical detail lives in a nested
// "service" property map (buildServiceProperties); fall back to flat keys.
func (b *AssetBridge) buildServiceEvent(a *asset.Asset) *exposure.ExposureEvent {
	props := a.Properties()
	svc := propMap(props, "service")
	if svc == nil {
		svc = props
	}

	port := propInt(svc, "port")
	name := propString(svc, "name")
	if name == "" {
		name = propString(props, "service")
	}
	if name == "" && port <= 0 {
		return nil // nothing identifying to track
	}

	protocol := propString(svc, "protocol")
	title := "Exposed service"
	switch {
	case name != "" && port > 0:
		title = fmt.Sprintf("Exposed service: %s (port %d)", name, port)
	case name != "":
		title = fmt.Sprintf("Exposed service: %s", name)
	default:
		title = fmt.Sprintf("Exposed service on port %d", port)
	}

	details := map[string]any{
		discoverySourceKey: SourceReconScan,
	}
	if port > 0 {
		details["port"] = port // whitelisted → dedupe key
	}
	if protocol != "" {
		details["protocol"] = protocol // whitelisted → dedupe key
	}
	if name != "" {
		details["service"] = name // whitelisted → dedupe key
	}
	if tv := propString(svc, "tls_version"); tv != "" {
		details["tls_version"] = tv
	}

	return b.newEvent(a, exposure.EventTypeServiceDetected, exposure.SeverityInfo, title, details,
		"Network service discovered by recon scan")
}

// buildCertificateEvents projects a certificate asset into expiry and/or
// weak-TLS exposures. Certificate detail lives in a nested "certificate"
// property map (buildCertificateProperties). Multiple issues on one cert yield
// multiple events, each with a distinct title (and therefore fingerprint).
func (b *AssetBridge) buildCertificateEvents(a *asset.Asset) []*exposure.ExposureEvent {
	cert := propMap(a.Properties(), "certificate")
	if cert == nil {
		return nil
	}

	subject := propString(cert, "subject_cn")
	label := subject
	if label == "" {
		label = a.Name()
	}

	baseDetails := func() map[string]any {
		d := map[string]any{discoverySourceKey: SourceReconScan}
		if subject != "" {
			d["subject_cn"] = subject
		}
		if na := propString(cert, "not_after"); na != "" {
			d["not_after"] = na
		}
		return d
	}

	var events []*exposure.ExposureEvent
	now := time.Now().UTC()

	// Expiry: prefer the parsed not_after; fall back to the scanner's expired flag.
	notAfter, hasNotAfter := parseTime(propString(cert, "not_after"))
	switch {
	case propBool(cert, "expired") || (hasNotAfter && notAfter.Before(now)):
		events = append(events, b.newEvent(a, exposure.EventTypeCertificateExpired, exposure.SeverityHigh,
			fmt.Sprintf("Certificate expired: %s", label), baseDetails(),
			"TLS certificate has expired (discovered by recon scan)"))
	case hasNotAfter && notAfter.Before(now.Add(certificateExpiryWindow)):
		events = append(events, b.newEvent(a, exposure.EventTypeCertificateExpiring, exposure.SeverityMedium,
			fmt.Sprintf("Certificate expiring soon: %s", label), baseDetails(),
			"TLS certificate expires within 30 days (discovered by recon scan)"))
	}

	// Weak-TLS posture: self-signed, weak RSA key, or a weak signature algorithm.
	if reason := weakTLSReason(cert); reason != "" {
		d := baseDetails()
		d["issue"] = reason
		events = append(events, b.newEvent(a, exposure.EventTypeSSLIssue, exposure.SeverityMedium,
			fmt.Sprintf("Weak TLS certificate (%s): %s", reason, label), d,
			"Weak TLS/SSL certificate posture (discovered by recon scan)"))
	}

	return events
}

// weakTLSReason returns a short reason string when the certificate has a weak
// posture, or "" when it looks fine. Only signals we can read cleanly are used,
// to avoid the CTEM-ID mislabel trap: a self-signed cert, a small RSA key, or a
// deprecated signature algorithm.
func weakTLSReason(cert map[string]any) string {
	if propBool(cert, "self_signed") {
		return "self-signed"
	}
	// Only judge key size for RSA — EC keys are legitimately much smaller.
	keyAlgo := strings.ToLower(propString(cert, "key_algorithm"))
	if strings.Contains(keyAlgo, "rsa") {
		if bits := propInt(cert, "key_size"); bits > 0 && bits < minRSAKeyBits {
			return "weak RSA key"
		}
	}
	sig := strings.ToLower(propString(cert, "signature_algorithm"))
	if strings.Contains(sig, "sha1") || strings.Contains(sig, "md5") {
		return "weak signature algorithm"
	}
	return ""
}

// newEvent constructs an exposure event linked to the source asset. SetAssetID
// recomputes the fingerprint so it embeds the (authoritative, persisted) asset
// id — call it before any consumer reads the fingerprint.
func (b *AssetBridge) newEvent(
	a *asset.Asset,
	eventType exposure.EventType,
	severity exposure.Severity,
	title string,
	details map[string]any,
	description string,
) *exposure.ExposureEvent {
	ev, err := exposure.NewExposureEvent(a.TenantID(), eventType, severity, title, SourceReconScan, details)
	if err != nil {
		b.logger.Warn("failed to build asset exposure event",
			"asset_id", a.ID().String(),
			"event_type", eventType.String(),
			"error", err,
		)
		return nil
	}
	aid := a.ID()
	ev.SetAssetID(&aid)
	if description != "" {
		ev.UpdateDescription(description)
	}
	return ev
}

// --- JSONB-safe property readers ---
// Properties round-trip through JSONB, so numbers come back as float64 and
// nested maps as map[string]any. These helpers read defensively across the
// shapes a value may take.

func propString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func propBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func propInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func propMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if sub, ok := m[key].(map[string]any); ok {
		return sub
	}
	return nil
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}
