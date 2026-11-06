package ingest

// A verified first-party tool that reports a type its signed descriptor does
// not declare is ingested, not held.
//
// The usual cause is a descriptor that lags its importer (the tool's next
// release declares the type). Holding such a report for a person's review
// only delays findings the tool was asked to produce. So, when ALL of these
// hold, the part of a report the catalog allows and the job's targets cover
// is applied normally, and the mismatch is flagged:
//
//   - the tool is one a released sensor compiles in and its contract claims
//     origin builtin (sensor.ToolTrust is "builtin");
//   - the sensor's grant is trusted;
//   - the sensor's current manifest was sent by the sensor and its descriptor
//     for the tool hashes to the contract digest (verifiedContract);
//   - the asset has a located type (a name, address, service, web
//     application) and one of the bound command's targets covers it.
//
// Everything else keeps its previous handling: an unsigned, third-party or
// untrusted descriptor or tool, an unverified sensor, an asset outside the
// command's targets or one with no location to check, dependencies and
// endpoints, and what the platform catalog does not allow for the tool, stay
// held for review (or are refused), and the quarantine caps still apply. A
// report from another tenant's sensor never reaches this code (the sensor is
// checked before). What is flagged: the receipt gets a contract_mismatch error
// entry per finding, the audit a sensor_result.contract_mismatch event, and
// the platform administrators one notice per (tool, type, tool version) a day.
//
// Follow-up: the descriptor is trusted as the sensor sent it (digest-checked,
// over the sensor's authenticated channel); a signed-release check of it is not
// part of this yet.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis/v2"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// mismatchNoticeEvery is how long one (tool, type, version) notice is not
// repeated.
const mismatchNoticeEvery = 24 * time.Hour

// MismatchNotifier tells the platform administrators (the notifier the
// coverage operator uses).
type MismatchNotifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

// SetMismatchNotifier wires the administrators' notice (nil: audit and log
// only).
func (s *Service) SetMismatchNotifier(n MismatchNotifier) { s.mismatch.notifier = n }

type mismatchNotices struct {
	notifier MismatchNotifier
	mu       sync.Mutex
	sent     map[string]time.Time
	now      func() time.Time
}

// due reports whether the key may be noticed now, and records it.
func (m *mismatchNotices) due(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	if m.sent == nil {
		m.sent = map[string]time.Time{}
	}
	if at, ok := m.sent[key]; ok && now.Sub(at) < mismatchNoticeEvery {
		return false
	}
	// Bound the memory: forget what is past its window.
	for k, at := range m.sent {
		if now.Sub(at) >= mismatchNoticeEvery {
			delete(m.sent, k)
		}
	}
	if len(m.sent) >= 1024 {
		return false
	}
	m.sent[key] = now
	return true
}

// contractMismatch is what a verified first-party tool reported without
// declaring it, in a report that was ingested.
type contractMismatch struct {
	// Types are "asset:<type>" and "finding:<type>" labels, sorted.
	Types []string
	// AssetRefs are the report refs of the assets of an undeclared type.
	AssetRefs map[string]bool
	// FindingTypes: a finding of an undeclared type is flagged by its own
	// type, not only by its asset.
	FindingTypes map[string]bool
}

// firstPartyContract returns the tool's verified contract when the tool is
// verified first-party (see the file comment), else nil.
func (s *Service) firstPartyContract(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, tool string) *sensor.ToolContract {
	if s.contracts == nil || s.grants == nil || agt == nil || agt.ID.IsZero() || tool == "" ||
		agt.TenantID == nil || *agt.TenantID != tenantID {
		return nil
	}
	v, err := s.contracts.CurrentManifest(ctx, &tenantID, agt.ID)
	if err != nil {
		return nil
	}
	c := verifiedContract(v, tool)
	if c == nil || sensor.ToolTrust(tool, c) != sensor.ToolTrustBuiltin {
		return nil
	}
	g, err := s.grants.Get(ctx, tenantID, agt.ID)
	if err != nil || g == nil || g.TrustLevel != sensor.TrustTrusted {
		return nil
	}
	return c
}

// jobCovers returns the check that an asset lies inside the command's
// targets (nil when the binding names none): it must have a located stored
// type and a locator one of the targets covers.
func jobCovers(b Binding) func(a *ctis.Asset) bool {
	if b.Kind != BindingCommand || len(b.Targets) == 0 {
		return func(*ctis.Asset) bool { return false }
	}
	scope := newAlterScope(b)
	return func(a *ctis.Asset) bool {
		rt := resolveCTISAssetType(a).stored
		if !locatedType(rt.Type) {
			return false
		}
		name := getAssetName(a)
		if host, _ := parseLocator(name); host == "" {
			return false
		}
		return scope.coversLocated(name, a.Properties)
	}
}

// flagMismatch lists what the report carries that the descriptor does not
// declare; nil when nothing.
func flagMismatch(r *ctis.Report, c *sensor.ToolContract) *contractMismatch {
	m := &contractMismatch{AssetRefs: map[string]bool{}, FindingTypes: map[string]bool{}}
	set := map[string]bool{}
	for i := range r.Assets {
		a := &r.Assets[i]
		if !c.Declares(sensor.ProduceAsset, string(a.Type)) {
			set[sensor.ProduceAsset+":"+sanitizeContractLabel(string(a.Type))] = true
			if a.ID != "" {
				m.AssetRefs[a.ID] = true
			}
		}
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if !c.Declares(sensor.ProduceFinding, string(f.Type)) {
			set[sensor.ProduceFinding+":"+sanitizeContractLabel(string(f.Type))] = true
			m.FindingTypes[string(f.Type)] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	for k := range set {
		m.Types = append(m.Types, k)
	}
	sort.Strings(m.Types)
	return m
}

// reportContractMismatch audits, counts and notices a flagged mismatch.
func (s *Service) reportContractMismatch(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, binding Binding,
	tool string, c *sensor.ToolContract, m *contractMismatch) {
	types := m.Types
	if len(types) > maxContractTypesLogged {
		types = types[:maxContractTypesLogged]
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("contract_mismatch_ingested").Inc()
	s.logger.Warn("verified first-party tool reported types its descriptor does not declare; ingested",
		"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", sanitizeIngestLogField(tool),
		"types", strings.Join(types, ","), "tool_version", sanitizeContractLabel(c.Version))
	event := auditapp.NewSuccessEvent(audit.ActionSensorResultContractMismatch, audit.ResourceTypeSensor, agt.ID.String()).
		WithResourceName(agt.Name).
		WithSeverity(audit.SeverityLow).
		WithMetadata("tool_name", tool).
		WithMetadata("tool_version", sanitizeContractLabel(c.Version)).
		WithMetadata("report_id", reportIDOf(ctx)).
		WithMetadata("types", types).
		WithMetadata("descriptor_digest", c.Digest).
		WithMessage(fmt.Sprintf("tool %s reported an undeclared type: %s; ingested", sanitizeContractLabel(tool), strings.Join(types, ", ")))
	if binding.CommandID != nil {
		event = event.WithMetadata("command_id", binding.CommandID.String())
	}
	s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()}, event)

	if s.mismatch.notifier == nil {
		return
	}
	for _, t := range m.Types {
		key := tool + "|" + t + "|" + c.Version
		if !s.mismatch.due(key) {
			continue
		}
		subject := "A first-party tool reported a type its descriptor does not declare"
		body := fmt.Sprintf("<p>Tool <b>%s</b> (version %s) reported <b>%s</b>, which its descriptor does not declare. "+
			"The results were ingested (they lie inside the job's targets). Fix the tool's descriptor in its next release.</p>",
			htmlEscape(sanitizeContractLabel(tool)), htmlEscape(sanitizeContractLabel(c.Version)), htmlEscape(t))
		go func() {
			nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if err := s.mismatch.notifier.NotifyAdmins(nctx, subject, body); err != nil {
				s.logger.Warn("contract mismatch notice not sent", "tool", sanitizeIngestLogField(tool), "error", err.Error())
			}
		}()
	}
}

func htmlEscape(v string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
}
