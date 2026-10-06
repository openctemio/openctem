package sensor

// Per-sensor grants (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §5): what one sensor may do, created from a profile and checked by the
// platform on every poll, claim and unsolicited result, whatever the sensor
// claims and even for a job a person scheduled. The trust level narrows it
// further (New: passive work only, no credentials, no push ingest).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Grant profiles.
const (
	ProfileLegacyBroad          = "legacy-broad"
	ProfileEASMExternal         = "easm-external"
	ProfileInternalScanner      = "internal-network-scanner"
	ProfileAuthenticatedScanner = "authenticated-scanner"
	ProfileCollector            = "collector"
	ProfileCIRunner             = "ci-runner"
	ProfileEndpoint             = "endpoint-agent"
	// ProfileCustom marks a grant edited away from its profile.
	ProfileCustom = "custom"

	// DefaultProfile is the profile an approval uses when none is chosen.
	DefaultProfile = ProfileInternalScanner
)

// TrustLevel is how far the platform trusts a sensor (RFC-052 §4 of
// research; SP3 adds restricted and quarantined).
type TrustLevel string

const (
	// TrustNew: just paired; passive work only, no credentials, no push.
	TrustNew TrustLevel = "new"
	// TrustTrusted: an administrator promoted it; the full grant applies.
	TrustTrusted TrustLevel = "trusted"
)

// TargetNetwork limits where a sensor's targets may be.
type TargetNetwork string

const (
	TargetNetworkAny    TargetNetwork = "any"
	TargetNetworkPublic TargetNetwork = "public" // no private, loopback or internal-suffix targets
	TargetNetworkNone   TargetNetwork = "none"   // no network targets at all
)

// Tiers (the stage catalog's T0/T1/T2).
const (
	TierPassive   = 0
	TierActive    = 1
	TierIntrusive = 2
)

// Remote actions. Narrowing actions are always allowed; gated ones only
// when the grant lists them.
var (
	alwaysAllowedActions = []string{"pause", "resume", "drain", "cancel", "send_manifest"}
	gatedActions         = []string{"update", "rotate_key", "diagnostics"}
	// workJobTypes are the command types a grant's job_types governs;
	// control types (health_check, cancel, refresh_content) are always
	// allowed: they carry no targets and only narrow or inspect.
	workJobTypes  = []string{"scan", "collect", "validate", "connector_sync", "connector_scan", "config_update"}
	controlJobTyp = []string{"health_check", "cancel", "refresh_content"}
)

// Grant dimensions, as named in refusals, audits and diffs.
const (
	DimTrust         = "trust_level"
	DimJobTypes      = "job_types"
	DimZones         = "zones"
	DimTools         = "tools"
	DimCapabilities  = "capabilities"
	DimTier          = "tier_ceiling"
	DimTargetNetwork = "target_network"
	DimTargetScope   = "target_scope"
	DimCredentials   = "credentials"
	DimPushIngest    = "push_ingest"
	DimRemoteActions = "remote_actions"
)

// ErrGrantInvalid is a grant that fails validation.
var ErrGrantInvalid = errors.New("invalid sensor grant")

// Grant is one sensor's grant. A nil slice means "no limit from the grant"
// on that dimension; an empty one means "nothing".
type Grant struct {
	TenantID shared.ID
	SensorID shared.ID
	Profile  string

	TrustLevel    TrustLevel
	JobTypes      []string
	ZoneIDs       []shared.ID
	Tools         []string
	Capabilities  []string
	TierCeiling   int
	TargetNetwork TargetNetwork
	TargetCIDRs   []string
	TargetDomains []string

	AllowCredentials bool
	AllowPushIngest  bool
	RemoteActions    []string

	Version   int
	UpdatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// LegacyBroad reports whether the grant is the broad grant every sensor that
// existed before RFC-052 got.
func (g *Grant) LegacyBroad() bool { return g != nil && g.Profile == ProfileLegacyBroad }

// SelectableProfiles are the profiles an administrator may pick for a sensor
// (legacy-broad is never selectable).
func SelectableProfiles() []string {
	return []string{ProfileInternalScanner, ProfileEASMExternal, ProfileAuthenticatedScanner,
		ProfileCollector, ProfileCIRunner, ProfileEndpoint}
}

// ValidProfile reports whether name may be picked ("collector:<name>" too).
func ValidProfile(name string) bool {
	base, param, has := strings.Cut(name, ":")
	if has {
		return base == ProfileCollector && isToken(param)
	}
	return slices.Contains(SelectableProfiles(), name)
}

// NewGrantFromProfile builds the grant of a profile at trust level New.
// zones are the zones chosen at approval: a zone-bound profile keeps to
// them; with none chosen it sets no zone limit (the zone assignment still
// decides which zoned work the sensor sees).
func NewGrantFromProfile(tenantID, sensorID shared.ID, profile string, zones []shared.ID) (*Grant, error) {
	if !ValidProfile(profile) {
		return nil, fmt.Errorf("%w: unknown profile %q", ErrGrantInvalid, profile)
	}
	g := &Grant{TenantID: tenantID, SensorID: sensorID, Profile: profile, TrustLevel: TrustNew,
		RemoteActions: []string{}, TargetNetwork: TargetNetworkAny, Version: 1}
	base, param, _ := strings.Cut(profile, ":")
	switch base {
	case ProfileEASMExternal:
		g.JobTypes, g.TierCeiling, g.TargetNetwork = []string{"scan"}, TierActive, TargetNetworkPublic
	case ProfileInternalScanner:
		g.JobTypes, g.TierCeiling = []string{"scan", "validate"}, TierActive
		g.ZoneIDs = zoneLimit(zones)
	case ProfileAuthenticatedScanner:
		g.JobTypes, g.TierCeiling, g.AllowCredentials = []string{"scan", "validate"}, TierActive, true
		g.ZoneIDs = zoneLimit(zones)
	case ProfileCollector:
		g.JobTypes, g.TierCeiling, g.TargetNetwork, g.AllowPushIngest = []string{"collect", "connector_sync"}, TierPassive, TargetNetworkNone, true
		if param != "" {
			g.Tools = []string{CanonicalTool(param)}
		}
	case ProfileCIRunner:
		g.JobTypes, g.TierCeiling, g.TargetNetwork, g.AllowPushIngest = []string{"scan"}, TierPassive, TargetNetworkNone, true
	case ProfileEndpoint:
		g.JobTypes, g.TierCeiling, g.TargetNetwork, g.AllowPushIngest = []string{"scan", "collect"}, TierPassive, TargetNetworkNone, true
	}
	return g, nil
}

func zoneLimit(zones []shared.ID) []shared.ID {
	if len(zones) == 0 {
		return nil
	}
	return append([]shared.ID{}, zones...)
}

// LegacyBroadGrant is the grant of a sensor that predates RFC-052 (and of
// platform sensors): no limit beyond the gates that existed before, trusted.
func LegacyBroadGrant(tenantID, sensorID shared.ID) *Grant {
	return &Grant{TenantID: tenantID, SensorID: sensorID, Profile: ProfileLegacyBroad, TrustLevel: TrustTrusted,
		TierCeiling: TierIntrusive, TargetNetwork: TargetNetworkAny, AllowCredentials: true, AllowPushIngest: true,
		RemoteActions: []string{"diagnostics", "rotate_key", "update"}, Version: 1}
}

// Effective applies the trust level: a New sensor gets passive work only,
// no credentials and no push ingest.
func (g Grant) Effective() Grant {
	if g.TrustLevel != TrustTrusted {
		g.TierCeiling = min(g.TierCeiling, TierPassive)
		g.AllowCredentials = false
		g.AllowPushIngest = false
	}
	return g
}

// Normalize canonicalises the lists (sorted, de-duplicated, lower-case
// tools and domains, masked CIDRs) and validates every dimension.
func (g *Grant) Normalize() error {
	if g.TrustLevel != TrustNew && g.TrustLevel != TrustTrusted {
		return fmt.Errorf("%w: trust level %q", ErrGrantInvalid, g.TrustLevel)
	}
	if g.TierCeiling < TierPassive || g.TierCeiling > TierIntrusive {
		return fmt.Errorf("%w: tier ceiling %d", ErrGrantInvalid, g.TierCeiling)
	}
	switch g.TargetNetwork {
	case TargetNetworkAny, TargetNetworkPublic, TargetNetworkNone:
	case "":
		g.TargetNetwork = TargetNetworkAny
	default:
		return fmt.Errorf("%w: target network %q", ErrGrantInvalid, g.TargetNetwork)
	}
	var err error
	if g.JobTypes, err = normList(g.JobTypes, func(s string) (string, bool) {
		s = strings.ToLower(strings.TrimSpace(s))
		return s, slices.Contains(workJobTypes, s)
	}); err != nil {
		return fmt.Errorf("%w: job type %v", ErrGrantInvalid, err)
	}
	if g.Tools, err = normList(g.Tools, func(s string) (string, bool) { s = CanonicalTool(s); return s, isToken(s) }); err != nil {
		return fmt.Errorf("%w: tool %v", ErrGrantInvalid, err)
	}
	if g.Capabilities, err = normList(g.Capabilities, func(s string) (string, bool) {
		s = strings.ToLower(strings.TrimSpace(s))
		return s, isToken(strings.ReplaceAll(s, ":", "_"))
	}); err != nil {
		return fmt.Errorf("%w: capability %v", ErrGrantInvalid, err)
	}
	if g.TargetCIDRs, err = normList(g.TargetCIDRs, func(s string) (string, bool) {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			a, aerr := netip.ParseAddr(strings.TrimSpace(s))
			if aerr != nil {
				return s, false
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		return p.Masked().String(), true
	}); err != nil {
		return fmt.Errorf("%w: CIDR %v", ErrGrantInvalid, err)
	}
	if g.TargetDomains, err = normList(g.TargetDomains, func(s string) (string, bool) {
		s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
		return s, isDomain(s)
	}); err != nil {
		return fmt.Errorf("%w: domain %v", ErrGrantInvalid, err)
	}
	if g.RemoteActions, err = normList(g.RemoteActions, func(s string) (string, bool) {
		s = strings.ToLower(strings.TrimSpace(s))
		return s, slices.Contains(gatedActions, s)
	}); err != nil {
		return fmt.Errorf("%w: remote action %v", ErrGrantInvalid, err)
	}
	if g.RemoteActions == nil {
		g.RemoteActions = []string{}
	}
	if len(g.ZoneIDs) > 0 {
		slices.SortFunc(g.ZoneIDs, func(a, b shared.ID) int { return strings.Compare(a.String(), b.String()) })
		g.ZoneIDs = slices.CompactFunc(g.ZoneIDs, func(a, b shared.ID) bool { return a == b })
	}
	if len(g.JobTypes) > 16 || len(g.Tools) > 64 || len(g.Capabilities) > 64 || len(g.TargetCIDRs) > 256 ||
		len(g.TargetDomains) > 256 || len(g.ZoneIDs) > 64 {
		return fmt.Errorf("%w: too many entries", ErrGrantInvalid)
	}
	return nil
}

func normList(in []string, norm func(string) (string, bool)) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		n, ok := norm(s)
		if !ok {
			return nil, fmt.Errorf("%q", s)
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func isToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func isDomain(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || !isToken(strings.ReplaceAll(label, "_", "-")) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

// GrantRefusal says which dimension refused a job and why.
type GrantRefusal struct {
	Dimension string
	Detail    string
}

func (r *GrantRefusal) Error() string {
	return "outside the sensor's grant (" + r.Dimension + "): " + r.Detail
}

// Admit checks one command against the effective grant. zoneID is the
// command's scan zone (nil when unzoned).
func (g Grant) Admit(cmdType string, payload json.RawMessage, zoneID *shared.ID) *GrantRefusal {
	e := g.Effective()
	t := strings.ToLower(strings.TrimSpace(cmdType))
	if slices.Contains(controlJobTyp, t) {
		return nil
	}
	if e.JobTypes != nil && !slices.Contains(e.JobTypes, t) {
		return &GrantRefusal{DimJobTypes, "job type " + t}
	}
	if zoneID != nil && e.ZoneIDs != nil && !slices.Contains(e.ZoneIDs, *zoneID) {
		return &GrantRefusal{DimZones, "zone " + zoneID.String()}
	}
	job := JobOf(t, payload)
	if e.Tools != nil && job.Tool != "" && !slices.Contains(e.Tools, job.Tool) {
		return &GrantRefusal{DimTools, "tool " + job.Tool}
	}
	if e.Capabilities != nil {
		for _, c := range requiredCapabilities(payload) {
			if !slices.Contains(e.Capabilities, c) {
				return &GrantRefusal{DimCapabilities, "capability " + c}
			}
		}
	}
	if tier := CommandTier(t, job); tier > e.TierCeiling {
		return &GrantRefusal{DimTier, fmt.Sprintf("tier T%d above the ceiling T%d", tier, e.TierCeiling)}
	}
	if r := e.admitTargets(payload); r != nil {
		return r
	}
	if !e.AllowCredentials && CarriesCredentials(payload) {
		return &GrantRefusal{DimCredentials, "the job carries credentials"}
	}
	return nil
}

func (g Grant) admitTargets(payload json.RawMessage) *GrantRefusal {
	targets, ok := payloadTargets(payload)
	if !ok {
		return &GrantRefusal{DimTargetScope, "targets unreadable"}
	}
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		switch g.TargetNetwork {
		case TargetNetworkNone:
			if isNetworkTarget(target) {
				return &GrantRefusal{DimTargetNetwork, "no network targets allowed"}
			}
			continue
		case TargetNetworkPublic:
			if isPrivateTarget(target) {
				return &GrantRefusal{DimTargetNetwork, "private target"}
			}
		}
		if g.TargetCIDRs == nil && g.TargetDomains == nil {
			continue
		}
		if !inTargetScope(target, g.TargetCIDRs, g.TargetDomains) {
			return &GrantRefusal{DimTargetScope, "target outside the scope"}
		}
	}
	return nil
}

// isNetworkTarget reports whether target names a host, address, range or
// URL (as opposed to a repository path or image reference for code and
// container scans).
func isNetworkTarget(target string) bool {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		return err != nil || (u.Scheme != "file" && u.Hostname() != "")
	}
	host := hostOf(target)
	if _, err := netip.ParsePrefix(host); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return true
	}
	return isDomain(strings.ToLower(host)) && !strings.Contains(target, "/")
}

func hostOf(target string) string {
	host := strings.TrimSpace(target)
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// inTargetScope reports whether target lies in one of cidrs or is one of
// domains (or below it). An address needs a CIDR, a name needs a domain: a
// name is never resolved here.
func inTargetScope(target string, cidrs, domains []string) bool {
	host := strings.Trim(hostOf(target), "[]")
	if p, err := netip.ParsePrefix(host); err == nil {
		p = p.Masked()
		for _, c := range cidrs {
			cp, _ := netip.ParsePrefix(c)
			if cp.Bits() <= p.Bits() && cp.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, c := range cidrs {
			if cp, _ := netip.ParsePrefix(c); cp.Contains(a) {
				return true
			}
		}
		return false
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func requiredCapabilities(payload json.RawMessage) []string {
	var p struct {
		Required []string `json:"required_capabilities"`
	}
	_ = json.Unmarshal(payload, &p)
	return p.Required
}

// CommandTier is how intrusive a command is: collect and connector_sync are
// T0, connector_scan and validate T1, a scan takes the lowest tier of the
// stages its tool implements (stage catalog); custom templates or
// out-of-band callbacks make any job T2, and a scan whose tool the catalog
// does not know is T2 (fail closed).
func CommandTier(cmdType string, job Job) int {
	if job.Interactsh || job.CustomTemplates > 0 {
		return TierIntrusive
	}
	switch cmdType {
	case "collect", "connector_sync", "health_check", "cancel", "refresh_content", "config_update":
		return TierPassive
	case "connector_scan", "validate":
		return TierActive
	}
	stages := stage.ForTool(job.Tool)
	if job.Tool == "" || len(stages) == 0 {
		return TierIntrusive
	}
	tier := TierIntrusive
	for _, s := range stages {
		tier = min(tier, int(s.Tier))
	}
	return tier
}

// CarriesCredentials reports whether a command's tool configuration holds
// credential-looking values (the scan config secret detector).
func CarriesCredentials(payload json.RawMessage) bool {
	var p struct {
		Config        map[string]any `json:"config"`
		ScannerConfig map[string]any `json:"scanner_config"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return true // unreadable: assume the worst
	}
	return len(scan.DetectConfigSecrets(p.Config)) > 0 || len(scan.DetectConfigSecrets(p.ScannerConfig)) > 0
}

// MayReceiveAction reports whether the platform may send action.
func (g Grant) MayReceiveAction(action string) bool {
	if slices.Contains(alwaysAllowedActions, action) {
		return true
	}
	return slices.Contains(g.RemoteActions, action)
}

// ---------------------------------------------------------------------------
// Narrowing and widening
// ---------------------------------------------------------------------------

// Widened lists the dimensions on which next allows something cur does not
// (sorted). An empty result means next only narrows or keeps cur.
func Widened(cur, next Grant) []string {
	var out []string
	add := func(d string, widened bool) {
		if widened {
			out = append(out, d)
		}
	}
	add(DimTrust, cur.TrustLevel == TrustNew && next.TrustLevel == TrustTrusted)
	add(DimJobTypes, listWidened(cur.JobTypes, next.JobTypes))
	add(DimZones, idListWidened(cur.ZoneIDs, next.ZoneIDs))
	add(DimTools, listWidened(cur.Tools, next.Tools))
	add(DimCapabilities, listWidened(cur.Capabilities, next.Capabilities))
	add(DimTier, next.TierCeiling > cur.TierCeiling)
	add(DimTargetNetwork, networkRank(next.TargetNetwork) > networkRank(cur.TargetNetwork))
	add(DimTargetScope, scopeWidened(cur, next))
	add(DimCredentials, next.AllowCredentials && !cur.AllowCredentials)
	add(DimPushIngest, next.AllowPushIngest && !cur.AllowPushIngest)
	add(DimRemoteActions, listWidened(nonNilList(cur.RemoteActions), nonNilList(next.RemoteActions)))
	return out
}

// Changed lists the dimensions that differ (sorted), for the audit diff.
func Changed(cur, next Grant) []string {
	var out []string
	add := func(d string, changed bool) {
		if changed {
			out = append(out, d)
		}
	}
	add(DimTrust, cur.TrustLevel != next.TrustLevel)
	add(DimJobTypes, !sameList(cur.JobTypes, next.JobTypes))
	add(DimZones, !sameIDs(cur.ZoneIDs, next.ZoneIDs))
	add(DimTools, !sameList(cur.Tools, next.Tools))
	add(DimCapabilities, !sameList(cur.Capabilities, next.Capabilities))
	add(DimTier, cur.TierCeiling != next.TierCeiling)
	add(DimTargetNetwork, cur.TargetNetwork != next.TargetNetwork)
	add(DimTargetScope, !sameList(cur.TargetCIDRs, next.TargetCIDRs) || !sameList(cur.TargetDomains, next.TargetDomains))
	add(DimCredentials, cur.AllowCredentials != next.AllowCredentials)
	add(DimPushIngest, cur.AllowPushIngest != next.AllowPushIngest)
	add(DimRemoteActions, !sameList(nonNilList(cur.RemoteActions), nonNilList(next.RemoteActions)))
	return out
}

func nonNilList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// listWidened: nil is "anything". next widens when it allows anything and
// cur did not, or names an entry cur did not.
func listWidened(cur, next []string) bool {
	if cur == nil {
		return false
	}
	if next == nil {
		return true
	}
	for _, n := range next {
		if !slices.Contains(cur, n) {
			return true
		}
	}
	return false
}

func idListWidened(cur, next []shared.ID) bool {
	if cur == nil {
		return false
	}
	if next == nil {
		return true
	}
	for _, n := range next {
		if !slices.Contains(cur, n) {
			return true
		}
	}
	return false
}

func sameList(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return slices.Equal(a, b)
}

func sameIDs(a, b []shared.ID) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return slices.Equal(a, b)
}

func networkRank(n TargetNetwork) int {
	switch n {
	case TargetNetworkNone:
		return 0
	case TargetNetworkPublic:
		return 1
	default:
		return 2
	}
}

// scopeWidened: no scope (nil CIDRs and domains) is "anything". next widens
// when it drops a scope cur had, or adds a CIDR or domain not covered by
// cur's.
func scopeWidened(cur, next Grant) bool {
	curAny := cur.TargetCIDRs == nil && cur.TargetDomains == nil
	nextAny := next.TargetCIDRs == nil && next.TargetDomains == nil
	if curAny {
		return false
	}
	if nextAny {
		return true
	}
	for _, c := range next.TargetCIDRs {
		if !inTargetScope(c, cur.TargetCIDRs, nil) {
			return true
		}
	}
	for _, d := range next.TargetDomains {
		if !inTargetScope(d, nil, cur.TargetDomains) {
			return true
		}
	}
	return false
}

// GrantSummary is the part of a grant the sensor list shows.
type GrantSummary struct {
	SensorID   shared.ID
	Profile    string
	TrustLevel TrustLevel
}

// GrantRepository stores sensors' grants. Every sensor has one: existing
// sensors got the legacy grant from the migration, a new one gets the
// narrowest default from a database trigger when it is inserted.
type GrantRepository interface {
	// Get returns the grant of a sensor of the tenant; shared.ErrNotFound
	// when the sensor is not the tenant's.
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*Grant, error)
	// Update writes g (its version + 1) if the stored version is still
	// g.Version (compare-and-swap); false when another change won or the
	// sensor is not the tenant's.
	Update(ctx context.Context, g *Grant) (bool, error)
	// ReplaceTx writes g inside tx whatever the stored version (the
	// approval of a pairing sets the chosen profile on the new sensor).
	ReplaceTx(ctx context.Context, tx *sql.Tx, g *Grant) error
}
