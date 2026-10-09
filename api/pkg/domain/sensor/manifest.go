package sensor

// The sensor manifest (docs/rfcs/RFC-033-sensor-manifest.md): what a sensor
// is, registered once and again on change, as opposed to its load, which
// every heartbeat carries. A manifest is a claim from an untrusted process:
// it is sanitized with the same catalog lookup as a heartbeat's capability
// report, its projection (the reported_* columns) can only narrow dispatch,
// and every distinct version is kept.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Manifest limits and constants.
const (
	// ManifestSchema is the manifest document version this server reads.
	ManifestSchema = 1
	// MaxManifestBytes caps a manifest document.
	MaxManifestBytes = 256 << 10
	// MaxManifestTargetTypes bounds one tool's target types.
	MaxManifestTargetTypes = 16
	// MaxManifestIgnored bounds the ignored items kept and returned.
	MaxManifestIgnored = 64
	// ManifestVersionsKept and ManifestVersionsMaxAge: versions beyond the
	// newest ManifestVersionsKept that are older than ManifestVersionsMaxAge
	// are pruned when a new version is stored.
	ManifestVersionsKept   = 50
	ManifestVersionsMaxAge = 90 * 24 * time.Hour
	// ManifestVersionsHardCap bounds the stored versions of one sensor
	// whatever their age: a sensor that changes its manifest on every call
	// (any unknown member changes the digest) must not grow the table
	// without bound within the retention age.
	ManifestVersionsHardCap = 100

	maxManifestCPUCores = 4096
	maxManifestStrLen   = 128
)

// Where a stored manifest came from.
const (
	// ManifestSourceSensor: the sensor sent it (PUT /api/v2/sensor/manifest).
	ManifestSourceSensor = "sensor"
	// ManifestSourceHeartbeat: the platform derived it from a heartbeat's
	// capability report (a sensor without manifest support).
	ManifestSourceHeartbeat = "heartbeat"
)

// Concurrency models a manifest may name.
const (
	ConcurrencyModelDynamic = "dynamic"
	ConcurrencyModelFixed   = "fixed"
)

// Reasons an item of a manifest is ignored.
const (
	IgnoredUnknownMember     = "unknown-member"
	IgnoredUnknownTool       = "unknown-tool"
	IgnoredInvalidName       = "invalid-name"
	IgnoredUnknownCapability = "unknown-capability"
	IgnoredLimit             = "limit"
)

// Errors of ParseManifest.
var (
	ErrManifestTooLarge          = errors.New("manifest too large")
	ErrManifestInvalid           = errors.New("manifest invalid")
	ErrManifestSchemaUnsupported = errors.New("manifest schema unsupported")
)

// Manifest is a sensor's self-description (RFC-033 §6.2). Every member is
// optional except Schema.
type Manifest struct {
	Schema       int                  `json:"schema"`
	Sensor       *ManifestBuild       `json:"sensor,omitempty"`
	SDK          *ManifestSDK         `json:"sdk,omitempty"`
	Platform     *ManifestPlatform    `json:"platform,omitempty"`
	Resources    *ManifestResources   `json:"resources,omitempty"`
	Concurrency  *ManifestConcurrency `json:"concurrency,omitempty"`
	Capabilities []string             `json:"capabilities,omitempty"`
	Tools        []ManifestTool       `json:"tools"`
	// LocalPolicy is the sensor-local policy report (RFC-040 §5.7), sent
	// by SDKs that see "local_policy" on hello; sanitized when stored.
	LocalPolicy *LocalPolicyReport `json:"local_policy,omitempty"`
}

// ManifestBuild is the sensor binary.
type ManifestBuild struct {
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
}

// ManifestSDK is the SDK the sensor is built with.
type ManifestSDK struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ManifestPlatform is the sensor's operating system and architecture.
type ManifestPlatform struct {
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
}

// ManifestResources is what the sensor may use (container limits when it
// runs in one). Display and selection input, not capacity.
type ManifestResources struct {
	CPUCores      float64 `json:"cpu_cores,omitempty"`
	MemTotalBytes int64   `json:"mem_total_bytes,omitempty"`
}

// ManifestConcurrency is the operator's ceiling (0: none) and how the sensor
// sizes its slots.
type ManifestConcurrency struct {
	Ceiling int    `json:"ceiling"`
	Model   string `json:"model,omitempty"`
}

// ManifestTool is one registered tool.
type ManifestTool struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind,omitempty"`
	Version      string            `json:"version,omitempty"`
	Installed    bool              `json:"installed"`
	Capabilities []string          `json:"capabilities,omitempty"`
	TargetTypes  []string          `json:"target_types,omitempty"`
	Content      []ManifestContent `json:"content,omitempty"`
	// Contract is the tool's tool-contract manifest: its digest and the
	// class, tier, network, consumes and produces it declares. Absent for a
	// tool not ported to the tool contract.
	Contract *ToolContract `json:"contract,omitempty"`
}

// ManifestContent is one piece of a tool's content (RFC-031), without the
// timestamps, which change on every refresh and stay on the heartbeat.
type ManifestContent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Source  string `json:"source,omitempty"`
	Managed bool   `json:"managed"`
}

// ManifestIgnored is one item of a manifest the platform dropped.
type ManifestIgnored struct {
	Path   string `json:"path"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

// ManifestVersion is one stored version of a sensor's manifest.
type ManifestVersion struct {
	SensorID shared.ID
	TenantID *shared.ID
	// Digest is "sha256:" + hex over the canonical document (ManifestDigest).
	Digest string
	// Source is ManifestSourceSensor or ManifestSourceHeartbeat.
	Source string
	// Manifest is the sanitized document.
	Manifest Manifest
	// Ignored lists what the sanitizing dropped.
	Ignored []ManifestIgnored
	// FirstSeenAt is when this version was first stored, CurrentSince when
	// it last became the current one, LastSeenAt when it was last confirmed.
	FirstSeenAt  time.Time
	CurrentSince time.Time
	LastSeenAt   time.Time
}

// ManifestDigest returns "sha256:" + the hex SHA-256 of the canonical form
// of a JSON document: object members sorted by name, no insignificant
// whitespace, no HTML escaping, numbers as written (RFC-033 §6.3).
func ManifestDigest(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: trailing data", ErrManifestInvalid)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// manifestMembers are the top-level members of schema 1.
var manifestMembers = map[string]bool{
	"schema": true, "sensor": true, "sdk": true, "platform": true, "resources": true,
	"concurrency": true, "capabilities": true, "tools": true, "local_policy": true,
}

// ParseManifest decodes a manifest leniently: unknown top-level members are
// returned as ignored items, not errors. It returns the digest of the
// document as received.
func ParseManifest(raw []byte) (Manifest, string, []ManifestIgnored, error) {
	var m Manifest
	if len(raw) > MaxManifestBytes {
		return m, "", nil, ErrManifestTooLarge
	}
	digest, err := ManifestDigest(raw)
	if err != nil {
		return m, "", nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return m, "", nil, fmt.Errorf("%w: not a JSON object", ErrManifestInvalid)
	}
	if _, ok := members["schema"]; !ok {
		return m, "", nil, fmt.Errorf("%w: schema is required", ErrManifestInvalid)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, "", nil, fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	if m.Schema != ManifestSchema {
		return m, "", nil, ErrManifestSchemaUnsupported
	}
	var ignored []ManifestIgnored
	for _, k := range sortedMemberNames(members) {
		if !manifestMembers[k] {
			ignored = append(ignored, ManifestIgnored{Path: truncate(k, maxManifestStrLen), Reason: IgnoredUnknownMember})
		}
	}
	return m, digest, ignored, nil
}

func sortedMemberNames(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// CapabilityInput is the manifest as a capability report, for the same
// sanitizing as a heartbeat's: its tools, and the flat capability list
// dispatch reads (the installed tools' names and capabilities plus the
// sensor-wide ones, the rule of sdk-go's ToolRegistry). A manifest is a
// complete statement: no tools means none.
func (m Manifest) CapabilityInput() CapabilityReportInput {
	in := CapabilityReportInput{
		Tools:        make([]ReportedTool, 0, min(len(m.Tools), MaxReportedTools)),
		Capabilities: []string{},
	}
	for i, t := range m.Tools {
		if i >= MaxReportedTools {
			break
		}
		rt := ReportedTool{Name: t.Name, Kind: t.Kind, Version: t.Version, Installed: t.Installed, Capabilities: t.Capabilities}
		if t.Capabilities == nil {
			rt.Capabilities = []string{}
		}
		for _, c := range t.Content {
			rt.Content = append(rt.Content, ReportedContent{Name: c.Name, Version: c.Version, Digest: c.Digest, Source: c.Source, Managed: c.Managed})
		}
		in.Tools = append(in.Tools, rt)
		if t.Installed {
			in.Capabilities = append(in.Capabilities, t.Name)
			in.Capabilities = append(in.Capabilities, t.Capabilities...)
		}
	}
	in.Capabilities = append(in.Capabilities, m.Capabilities...)
	if m.Concurrency != nil {
		in.MaxConcurrentJobs = m.Concurrency.Ceiling
	}
	if m.Platform != nil {
		in.OS, in.Arch = m.Platform.OS, m.Platform.Arch
	}
	return in
}

// Sanitized is what is stored of m: the tools and capabilities that
// survived sanitizing (rep, from CapabilityInput().Sanitize), the build as
// ResolveBuild reads it, and the rest clamped. It also returns what was
// ignored.
func (m Manifest) Sanitized(rep CapabilityReport, now time.Time) (Manifest, []ManifestIgnored) {
	out := Manifest{Schema: ManifestSchema, Tools: []ManifestTool{}}
	if lp := SanitizeLocalPolicyReport(m.LocalPolicy); lp != nil {
		lp.KillSwitch = false // live state: the heartbeat's, never the manifest's
		out.LocalPolicy = lp
	}
	var ignored []ManifestIgnored
	ignore := func(path, value, reason string) {
		if len(ignored) < MaxManifestIgnored {
			ignored = append(ignored, ManifestIgnored{Path: path, Value: truncate(value, maxManifestStrLen), Reason: reason})
		}
	}

	var br BuildReport
	if m.Sensor != nil {
		br.SensorName, br.SensorVersion, br.Commit, br.BuildTime = m.Sensor.Name, m.Sensor.Version, m.Sensor.Commit, m.Sensor.BuildTime
	}
	if m.SDK != nil {
		br.SDKName, br.SDKVersion = m.SDK.Name, m.SDK.Version
	}
	version := ""
	if m.Sensor != nil {
		version = m.Sensor.Version
	}
	build, v := ResolveBuild(br, version, "", now)
	out.Sensor, out.SDK = manifestBuildOf(build, v)

	if rep.OS != "" || rep.Arch != "" {
		out.Platform = &ManifestPlatform{OS: rep.OS, Arch: rep.Arch}
	}
	if r := m.Resources; r != nil && (r.CPUCores > 0 || r.MemTotalBytes > 0) {
		out.Resources = &ManifestResources{CPUCores: min(max(r.CPUCores, 0), maxManifestCPUCores), MemTotalBytes: max(r.MemTotalBytes, 0)}
	}
	if c := m.Concurrency; c != nil {
		cc := ManifestConcurrency{Ceiling: rep.MaxConcurrentJobs}
		if c.Model == ConcurrencyModelDynamic || c.Model == ConcurrencyModelFixed {
			cc.Model = c.Model
		}
		out.Concurrency = &cc
	}

	kept := make(map[string]ReportedTool, len(rep.Tools))
	for _, t := range rep.Tools {
		kept[t.Name] = t
	}
	seen := map[string]bool{}
	for i, t := range m.Tools {
		path := fmt.Sprintf("tools[%d]", i)
		if i >= MaxReportedTools {
			ignore(path, t.Name, IgnoredLimit)
			continue
		}
		name := strings.ToLower(strings.TrimSpace(t.Name))
		rt, ok := kept[name]
		switch {
		case !validToolName(name):
			ignore(path, t.Name, IgnoredInvalidName)
			continue
		case !ok:
			ignore(path, t.Name, IgnoredUnknownTool)
			continue
		}
		for j, c := range t.Capabilities {
			if !slices.Contains(rt.Capabilities, strings.ToLower(strings.TrimSpace(c))) {
				reason := IgnoredUnknownCapability
				if j >= MaxReportedToolCapabilities {
					reason = IgnoredLimit
				}
				ignore(fmt.Sprintf("%s.capabilities[%d]", path, j), c, reason)
			}
		}
		if seen[name] {
			continue // a second entry for the tool: merged by Sanitize
		}
		seen[name] = true
		mt := ManifestTool{Name: rt.Name, Kind: rt.Kind, Version: rt.Version, Installed: rt.Installed,
			Capabilities: rt.Capabilities, TargetTypes: sanitizeTargetTypes(t.TargetTypes)}
		for _, c := range rt.Content {
			mt.Content = append(mt.Content, ManifestContent{Name: c.Name, Version: c.Version, Digest: c.Digest, Source: c.Source, Managed: c.Managed})
		}
		if t.Contract != nil {
			if c, why := SanitizeToolContract(t.Contract); c != nil {
				mt.Contract = c
				if d, why := SanitizeToolDescriptor(c, t.Contract.Descriptor); d != nil {
					c.Descriptor = d
				} else if why != "" {
					ignore(path+".contract.descriptor", why, IgnoredInvalidDescriptor)
				}
			} else {
				ignore(path+".contract", why, IgnoredInvalidContract)
			}
		}
		out.Tools = append(out.Tools, mt)
	}
	for k, c := range m.Capabilities {
		norm := strings.ToLower(strings.TrimSpace(c))
		if slices.Contains(rep.Capabilities, norm) {
			if !slices.Contains(out.Capabilities, norm) {
				out.Capabilities = append(out.Capabilities, norm)
			}
			continue
		}
		ignore(fmt.Sprintf("capabilities[%d]", k), c, IgnoredUnknownCapability)
	}
	return out, ignored
}

// ManifestFromReport derives a manifest from a sanitized heartbeat report
// and the build the heartbeat resolved to (RFC-033 §6.6): what a sensor
// without manifest support has said about itself. Sensor-wide capabilities
// are the reported ones no installed tool provides.
func ManifestFromReport(rep CapabilityReport, build BuildInfo, version string) Manifest {
	m := Manifest{Schema: ManifestSchema, Tools: []ManifestTool{}}
	m.Sensor, m.SDK = manifestBuildOf(build, version)
	if rep.OS != "" || rep.Arch != "" {
		m.Platform = &ManifestPlatform{OS: rep.OS, Arch: rep.Arch}
	}
	if rep.MaxConcurrentJobs > 0 {
		m.Concurrency = &ManifestConcurrency{Ceiling: rep.MaxConcurrentJobs}
	}
	provided := map[string]bool{}
	for _, t := range rep.Tools {
		mt := ManifestTool{Name: t.Name, Kind: t.Kind, Version: t.Version, Installed: t.Installed, Capabilities: t.Capabilities}
		for _, c := range t.Content {
			mt.Content = append(mt.Content, ManifestContent{Name: c.Name, Version: c.Version, Digest: c.Digest, Source: c.Source, Managed: c.Managed})
		}
		m.Tools = append(m.Tools, mt)
		if t.Installed {
			provided[t.Name] = true
			for _, c := range t.Capabilities {
				provided[c] = true
			}
		}
	}
	for _, c := range rep.Capabilities {
		if !provided[c] {
			m.Capabilities = append(m.Capabilities, c)
		}
	}
	return m
}

// Digest is the manifest's digest (ManifestDigest of its JSON encoding).
func (m Manifest) Digest() (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	return ManifestDigest(raw)
}

// AcceptedToolNames returns the names of the manifest's tools.
func (m Manifest) AcceptedToolNames() []string {
	out := make([]string, 0, len(m.Tools))
	for _, t := range m.Tools {
		out = append(out, t.Name)
	}
	return out
}

func manifestBuildOf(build BuildInfo, version string) (*ManifestBuild, *ManifestSDK) {
	var sb *ManifestBuild
	if build.Product != "" || version != "" || build.Commit != "" || build.BuildTime != nil {
		sb = &ManifestBuild{Name: build.Product, Version: version, Commit: build.Commit}
		if build.BuildTime != nil {
			sb.BuildTime = build.BuildTime.UTC().Format(time.RFC3339)
		}
	}
	var sdk *ManifestSDK
	if build.SDKName != "" || build.SDKVersion != "" {
		sdk = &ManifestSDK{Name: build.SDKName, Version: build.SDKVersion}
	}
	return sb, sdk
}

var targetTypeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// sanitizeTargetTypes keeps well-formed target type names (Phase 3 checks
// them against the asset-type registry), deduplicated and capped.
func sanitizeTargetTypes(in []string) []string {
	var out []string
	for i, t := range in {
		if i >= MaxManifestTargetTypes {
			break
		}
		t = strings.ToLower(strings.TrimSpace(t))
		if len(t) <= MaxReportedCapLen && targetTypeRe.MatchString(t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ManifestPolicy is what the platform lets the sensor run (RFC-033 §6.12,
// owner decision O2): its effective tools, capabilities and capacity, the
// report narrowed by the administrator's settings. The SDK refuses commands
// for tools outside AllowedTools.
type ManifestPolicy struct {
	AllowedTools        []string `json:"allowed_tools"`
	AllowedCapabilities []string `json:"allowed_capabilities"`
	MaxJobs             int      `json:"max_jobs"`
}

// ManifestPolicy returns the sensor's policy as it stands.
func (a *Sensor) ManifestPolicy() ManifestPolicy {
	return ManifestPolicy{
		AllowedTools:        a.EffectiveTools(),
		AllowedCapabilities: a.EffectiveCapabilities(),
		MaxJobs:             a.EffectiveMaxConcurrentJobs(),
	}
}

// ManifestDiff is what changed between two manifests (RFC-033 §6.12). Content
// versions are left out: they have their own content_updated events.
type ManifestDiff struct {
	ToolsAdded   []string         `json:"tools_added,omitempty"`
	ToolsRemoved []string         `json:"tools_removed,omitempty"`
	Versions     []ManifestChange `json:"versions,omitempty"`
	Installed    []ManifestChange `json:"installed,omitempty"`
	// Contracts are tools whose tool-contract digest changed ("" when absent).
	Contracts    []ManifestChange  `json:"contracts,omitempty"`
	Capabilities []ManifestCapDiff `json:"capabilities,omitempty"`
	// SensorWide is the change of the sensor-wide capabilities.
	SensorWide *ManifestCapDiff `json:"sensor_wide,omitempty"`
	// Other names other members that changed: "build", "sdk", "platform",
	// "resources", "concurrency".
	Other []string `json:"other,omitempty"`
}

// ManifestChange is a tool whose value changed.
type ManifestChange struct {
	Tool string `json:"tool"`
	From string `json:"from"`
	To   string `json:"to"`
}

// ManifestCapDiff is the capabilities a tool (or the sensor) gained and lost.
type ManifestCapDiff struct {
	Tool    string   `json:"tool,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// IsEmpty reports whether nothing worth an event changed.
func (d ManifestDiff) IsEmpty() bool {
	return len(d.ToolsAdded) == 0 && len(d.ToolsRemoved) == 0 && len(d.Versions) == 0 &&
		len(d.Installed) == 0 && len(d.Contracts) == 0 && len(d.Capabilities) == 0 && d.SensorWide == nil && len(d.Other) == 0
}

// DiffManifests compares two manifests.
func DiffManifests(prev, next Manifest) ManifestDiff {
	var d ManifestDiff
	before := make(map[string]ManifestTool, len(prev.Tools))
	for _, t := range prev.Tools {
		before[t.Name] = t
	}
	after := make(map[string]bool, len(next.Tools))
	for _, t := range next.Tools {
		after[t.Name] = true
		p, ok := before[t.Name]
		if !ok {
			d.ToolsAdded = append(d.ToolsAdded, t.Name)
			continue
		}
		if p.Version != t.Version {
			d.Versions = append(d.Versions, ManifestChange{Tool: t.Name, From: p.Version, To: t.Version})
		}
		if pd, td := contractDigest(p.Contract), contractDigest(t.Contract); pd != td {
			d.Contracts = append(d.Contracts, ManifestChange{Tool: t.Name, From: pd, To: td})
		}
		if p.Installed != t.Installed {
			d.Installed = append(d.Installed, ManifestChange{Tool: t.Name, From: installedWord(p.Installed), To: installedWord(t.Installed)})
		}
		if added, removed := listDiff(p.Capabilities, t.Capabilities); len(added)+len(removed) > 0 {
			d.Capabilities = append(d.Capabilities, ManifestCapDiff{Tool: t.Name, Added: added, Removed: removed})
		}
	}
	for _, t := range prev.Tools {
		if !after[t.Name] {
			d.ToolsRemoved = append(d.ToolsRemoved, t.Name)
		}
	}
	if added, removed := listDiff(prev.Capabilities, next.Capabilities); len(added)+len(removed) > 0 {
		d.SensorWide = &ManifestCapDiff{Added: added, Removed: removed}
	}
	for _, o := range []struct {
		name string
		a, b any
	}{
		{"build", prev.Sensor, next.Sensor}, {"sdk", prev.SDK, next.SDK}, {"platform", prev.Platform, next.Platform},
		{"resources", prev.Resources, next.Resources}, {"concurrency", prev.Concurrency, next.Concurrency},
	} {
		if !jsonEqual(o.a, o.b) {
			d.Other = append(d.Other, o.name)
		}
	}
	return d
}

// Summary is a plain-English line for the activity timeline.
func (d ManifestDiff) Summary() string {
	parts := make([]string, 0, len(d.ToolsAdded)+len(d.Versions)+len(d.Installed)+4)
	if len(d.ToolsAdded) > 0 {
		parts = append(parts, "added "+strings.Join(d.ToolsAdded, ", "))
	}
	if len(d.ToolsRemoved) > 0 {
		parts = append(parts, "removed "+strings.Join(d.ToolsRemoved, ", "))
	}
	for _, v := range d.Versions {
		parts = append(parts, fmt.Sprintf("%s %s → %s", v.Tool, orNone(v.From), orNone(v.To)))
	}
	for _, i := range d.Installed {
		parts = append(parts, fmt.Sprintf("%s %s", i.Tool, i.To))
	}
	if n := len(d.Contracts); n > 0 {
		parts = append(parts, fmt.Sprintf("tool contract of %d changed", n))
	}
	if n := len(d.Capabilities); n > 0 || d.SensorWide != nil {
		if d.SensorWide != nil {
			n++
		}
		parts = append(parts, fmt.Sprintf("capabilities of %d changed", n))
	}
	if len(d.Other) > 0 {
		parts = append(parts, strings.Join(d.Other, ", ")+" changed")
	}
	if len(parts) == 0 {
		return "Manifest changed"
	}
	// sensor_events.summary is VARCHAR(500); the details carry everything.
	return truncate("Manifest changed: "+strings.Join(parts, "; "), maxManifestSummaryLen)
}

const maxManifestSummaryLen = 480

func listDiff(prev, next []string) (added, removed []string) {
	for _, c := range next {
		if !slices.Contains(prev, c) {
			added = append(added, c)
		}
	}
	for _, c := range prev {
		if !slices.Contains(next, c) {
			removed = append(removed, c)
		}
	}
	return added, removed
}

func jsonEqual(a, b any) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ra, rb)
}

func contractDigest(c *ToolContract) string {
	if c == nil {
		return ""
	}
	return c.Digest
}

func installedWord(installed bool) string {
	if installed {
		return "installed"
	}
	return "not installed"
}

func orNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}
