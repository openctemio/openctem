package retest

// Retest strategy by provenance (docs/architecture/finding-retest-strategy.md):
// how a finding is re-checked follows from what raised it.
//
//   - template: a scanner rule (a nuclei template, or a rule of a tool with
//     a retest handler) is re-run against the finding's target;
//   - custom_check: a retest check attached to the finding is run;
//   - version_recheck: a finding the platform's version matcher raised
//     (software version × CVE ranges) is re-checked by re-running the
//     fingerprint that read the version and evaluating the version seen;
//   - none: a person reported it, or nothing can re-check it automatically;
//     the console shows why instead of starting a job that fails.

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Strategy kinds (stable API values).
const (
	StrategyTemplate       = "template"
	StrategyCustomCheck    = "custom_check"
	StrategyVersionRecheck = "version_recheck"
	StrategyNone           = "none"
)

// Request modes.
const (
	// ModeDefault re-checks the finding with its strategy.
	ModeDefault = ""
	// ModeActiveCheck runs, for a version-match finding, the installed
	// template named after its CVE instead of the version re-check.
	ModeActiveCheck = "active_check"
)

// More reason codes (see availability.go).
const (
	// ReasonNoAutomaticRetest: a person reported the finding (manual,
	// pentest, bug bounty, red team); a retest check makes it retestable.
	ReasonNoAutomaticRetest = "no_automatic_retest"
	// ReasonImportedNoRetest: the finding was imported from a tool no
	// sensor of the organization can re-run.
	ReasonImportedNoRetest = "imported_no_retest"
	// ReasonVersionEvidenceMissing: a version-match finding whose software
	// link (product, version, location) is no longer known.
	ReasonVersionEvidenceMissing = "version_evidence_missing"
	// ReasonVersionSourceNotRescannable: the version came from a source no
	// network fingerprint re-reads (an SBOM package, the operating system).
	ReasonVersionSourceNotRescannable = "version_source_not_rescannable"
	// ReasonNoTemplateSensor: every online sensor that could retest reports
	// an older template release than the one the finding was found with.
	ReasonNoTemplateSensor = "no_template_sensor"
	// ReasonActiveCheckUnavailable: no installed template is known to test
	// the finding's CVE on an online sensor of the organization.
	ReasonActiveCheckUnavailable = "active_check_unavailable"
)

// Fingerprint tools: the sensor tools whose output carries the software
// versions the matcher reads (RFC-066 §6).
const (
	fingerprintHTTP = "httpx" // technologies and the Server header
	fingerprintPort = "naabu" // a port's service and version
)

// Strategy says how a finding is re-checked.
type Strategy struct {
	Kind string `json:"kind"`
	// Rule is the template or rule re-run (template, custom_check) or the
	// CVE evaluated (version_recheck).
	Rule string `json:"rule,omitempty"`
	// Tool is the tool that re-checks: nuclei or the finding's tool, or the
	// fingerprint tool of a version re-check.
	Tool string `json:"tool,omitempty"`
	// Product and Version are the software a version re-check compares.
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
}

// ActiveCheck is the optional template run offered for a version-match
// finding when a template named after its CVE is known to be installed on
// an online sensor of the organization (it ran there before).
type ActiveCheck struct {
	Template  string `json:"template"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Offer is what the console shows for a finding: the strategy, whether a
// retest would be accepted now, why not, and an optional active check.
type Offer struct {
	Strategy    Strategy
	Available   bool
	Reason      string
	ActiveCheck *ActiveCheck
}

// VersionEvidence reads the software links behind version-match findings
// (*postgres.SoftwareMatchRepository). Every method is tenant-scoped except
// RangesForProduct, which reads the global corpus.
type VersionEvidence interface {
	FindingLink(ctx context.Context, tenantID, findingID shared.ID) (*softwarematch.FindingLink, error)
	ObservedSince(ctx context.Context, tenantID, assetID, productID shared.ID, location string, since time.Time) ([]softwarematch.ObservedVersion, error)
	RangesForProduct(ctx context.Context, productID shared.ID) ([]softwarematch.AffectedRange, error)
}

// Fingerprinter starts the fingerprint scan of a version re-check: an ad-hoc
// scan of one target with one tool, through the scan service's target gates
// (scope, ownership, tier). Returns the scan run.
type Fingerprinter interface {
	StartFingerprint(ctx context.Context, tenantID shared.ID, tool, target string, requestedBy *shared.ID) (shared.ID, error)
}

// RunReader reads a scan run of a tenant.
type RunReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scanrun.Run, error)
}

// TemplateEvidence answers which sensors of the tenant reported a finding of
// a rule with a tool (*postgres.FindingRepository): they have that
// template installed.
type TemplateEvidence interface {
	TemplateSightingSensors(ctx context.Context, tenantID shared.ID, tool, ruleID string, limit int) ([]shared.ID, error)
}

// SensorCandidate is an online sensor of the tenant, with capacity, that has
// the capabilities a retest needs, and the template release it reports.
type SensorCandidate struct {
	ID               shared.ID
	TemplatesVersion string
}

// SensorCandidates is the optional part of SensorAvailability that lists
// the sensors (so a retest can be addressed to one that has the template)
// and answers whether a sensor runs a tool.
type SensorCandidates interface {
	RetestSensors(ctx context.Context, tenantID shared.ID, capabilities []string) ([]SensorCandidate, error)
	HasToolSensor(ctx context.Context, tenantID shared.ID, tool string) (bool, error)
}

// SetVersionRecheck wires the version re-check of version-match findings.
func (s *Service) SetVersionRecheck(v VersionEvidence, f Fingerprinter, runs RunReader) {
	s.versions, s.fingerprinter, s.runReader = v, f, runs
}

// SetTemplateEvidence wires the template sightings (sensor selection and the
// active check).
func (s *Service) SetTemplateEvidence(e TemplateEvidence) { s.templates = e }

// humanSources are reported by people: nothing re-runs them automatically.
var humanSources = map[vulnerability.FindingSource]bool{
	vulnerability.FindingSourceManual: true, vulnerability.FindingSourcePentest: true,
	vulnerability.FindingSourceBugBounty: true, vulnerability.FindingSourceRedTeam: true,
}

// isHumanFinding: a person reported the finding.
func isHumanFinding(f *vulnerability.Finding) bool {
	return humanSources[f.Source()] || f.IngestChannel() == vulnerability.IngestChannelManual
}

// isImported: the finding came from an integration or a collector, not a
// scan of the organization's sensors.
func isImported(f *vulnerability.Finding) bool {
	ch := f.IngestChannel()
	return ch == vulnerability.IngestChannelIntegration || ch == vulnerability.IngestChannelCollector
}

// isVersionMatch: the platform's version matcher raised the finding and no
// scanner has reported it since (the matcher still owns it).
func isVersionMatch(f *vulnerability.Finding) bool {
	return tooldom.SameTool(f.ToolName(), softwarematch.ToolName) && tooldom.SameTool(f.LastSeenTool(), softwarematch.ToolName)
}

// recheckTool is the tool a finding's rule is re-run with: its own tool,
// or for a version-match finding a scanner has reported since, that
// scanner (it re-runs its own rule).
func recheckTool(f *vulnerability.Finding) string {
	if tooldom.SameTool(f.ToolName(), softwarematch.ToolName) {
		return strings.ToLower(strings.TrimSpace(f.LastSeenTool()))
	}
	return findingTool(f)
}

// fingerprintToolFor is the tool that re-reads a link's version: the HTTP
// probe for a technology or a Server header, the port scanner for a port's
// service. "" when no network fingerprint re-reads it (package, os).
func fingerprintToolFor(link *softwarematch.FindingLink) string {
	switch link.Source {
	case "technology":
		return fingerprintHTTP
	case "service":
		if link.Location == "" && link.Port == 0 {
			return fingerprintHTTP // the HTTP Server header
		}
		return fingerprintPort
	case "open_port":
		return fingerprintPort
	}
	return ""
}

// fingerprintTarget is what the fingerprint scans: the asset's host, with
// the link's port when it has one.
func fingerprintTarget(assetName string, link *softwarematch.FindingLink) string {
	host := hostOf(assetName)
	if host == "" {
		return ""
	}
	port := link.Port
	if port == 0 {
		if _, p, ok := strings.Cut(link.Location, "/"); ok {
			port, _ = strconv.Atoi(p)
		}
	}
	if port > 0 && port <= 65535 {
		if strings.Contains(host, ":") {
			return "[" + host + "]:" + strconv.Itoa(port)
		}
		return host + ":" + strconv.Itoa(port)
	}
	return host
}

// PickTemplateSensor chooses the sensor a template retest is addressed to:
// the sensor that last reported the finding (it ran the template), else the
// candidate with the newest template release at or above the release the
// finding was found with, else one that reports no release. ok is false
// when every candidate reports an older release than the finding's.
// pin is nil when no choice is needed (no release to compare and no
// sighting sensor online): any capable sensor may claim the command.
func PickTemplateSensor(cands []SensorCandidate, sighting *shared.ID, findingRelease string) (pin *shared.ID, ok bool) {
	if len(cands) == 0 {
		// Nothing to choose from (the capability check already passed).
		return nil, true
	}
	if sighting != nil {
		for _, c := range cands {
			if c.ID == *sighting {
				id := c.ID
				return &id, true
			}
		}
	}
	if strings.TrimSpace(findingRelease) == "" {
		return nil, true
	}
	var best, unknown *SensorCandidate
	for i := range cands {
		c := &cands[i]
		cmp, known := compareRelease(c.TemplatesVersion, findingRelease)
		switch {
		case !known:
			if unknown == nil {
				unknown = c
			}
		case cmp >= 0:
			if best == nil {
				best = c
			} else if b, _ := compareRelease(c.TemplatesVersion, best.TemplatesVersion); b > 0 {
				best = c
			}
		}
	}
	switch {
	case best != nil:
		id := best.ID
		return &id, true
	case unknown != nil:
		id := unknown.ID
		return &id, true
	}
	return nil, false
}

// compareRelease compares two template releases ("v10.2.7"): -1, 0, 1, and
// whether both parse as dotted numbers.
func compareRelease(a, b string) (int, bool) {
	pa, oka := parseRelease(a)
	pb, okb := parseRelease(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x < y:
			return -1, true
		case x > y:
			return 1, true
		}
	}
	return 0, true
}

func parseRelease(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(v)), "v")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	if len(parts) > 6 {
		return nil, false
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// templatesVersionOf is the nuclei template release a sensor reports.
func templatesVersionOf(s *sensordom.Sensor) string {
	for _, c := range s.ReportedContent() {
		if c.Name == sensordom.ContentNucleiTemplates {
			return c.Version
		}
	}
	return ""
}

// CandidatesOf lists sensors as retest candidates (for SensorCandidates
// implementations).
func CandidatesOf(sensors []*sensordom.Sensor) []SensorCandidate {
	out := make([]SensorCandidate, 0, len(sensors))
	for _, s := range sensors {
		out = append(out, SensorCandidate{ID: s.ID, TemplatesVersion: templatesVersionOf(s)})
	}
	return out
}
