package ingest

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetCorrelator resolves incoming assets against existing ones using
// alternative identifiers beyond name (IP addresses, external IDs, etc.).
// Part of RFC-001: Asset Identity Resolution.
type AssetCorrelator struct {
	repo   CorrelationRepo
	logger *logger.Logger
	config CorrelationConfig
}

// CorrelationRepo defines the repository methods needed for correlation.
type CorrelationRepo interface {
	FindByIPs(ctx context.Context, tenantID shared.ID, ips []string) (map[string][]*asset.Asset, error)
	FindByHostname(ctx context.Context, tenantID shared.ID, hostname string) (*asset.Asset, error)
	FindByExternalID(ctx context.Context, tenantID shared.ID, externalID string) (*asset.Asset, error)
	FindByPropertyValue(ctx context.Context, tenantID shared.ID, key, value string) (*asset.Asset, error)
	FindRepositoryByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*asset.Asset, error)
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error)
}

// DefaultIPTrustWindowDays is how recently an existing asset must have been
// seen for an IP match to count. An IP is the weakest host identifier: DHCP
// hands the same address to another machine, and a match outside this window
// would merge (and rename) the wrong host. Owner decision 2026-10-01: 7 days,
// down from 30.
const DefaultIPTrustWindowDays = 7

// DefaultMaxIPsPerAsset is the system default for CorrelationConfig.MaxIPsPerAsset.
const DefaultMaxIPsPerAsset = 20

// CorrelationConfig controls correlation behavior.
// System defaults are set at startup; per-tenant overrides can be passed
// via WithTenantOverrides() before calling CorrelateHost().
type CorrelationConfig struct {
	// StaleAssetDays is the IP trust window: an IP match counts only when the
	// existing asset was seen within this many days
	// (default: DefaultIPTrustWindowDays).
	StaleAssetDays int
	MaxIPsPerAsset int // Skip correlation if asset has > N IPs (default: 20)
}

// WithTenantOverrides returns a copy with tenant-specific values applied.
// Zero values in tenant config mean "use system default".
func (c CorrelationConfig) WithTenantOverrides(tenantStale, tenantMaxIPs int) CorrelationConfig {
	cfg := c
	if tenantStale > 0 {
		cfg.StaleAssetDays = tenantStale
	}
	if tenantMaxIPs > 0 {
		cfg.MaxIPsPerAsset = tenantMaxIPs
	}
	return cfg
}

// CorrelationResult tells the caller what to do with the incoming asset.
type CorrelationResult struct {
	// Matched is the existing asset to merge into. nil = create new.
	Matched *asset.Asset

	// ShouldRename indicates the matched asset should be renamed to a better name.
	ShouldRename bool
	NewName      string

	// Ambiguous lists the assets an IP matched when it matched more than one
	// (most findings first). Matched is nil then: the match does not count,
	// and the caller raises a duplicate review for these assets.
	Ambiguous []*asset.Asset

	// CorrelationType records how the match was found (for audit log).
	CorrelationType string // "ip", "hostname", "external_id", "fingerprint"
}

// NewAssetCorrelator creates a new correlator.
func NewAssetCorrelator(repo CorrelationRepo, log *logger.Logger, cfg CorrelationConfig) *AssetCorrelator {
	if cfg.StaleAssetDays <= 0 {
		cfg.StaleAssetDays = DefaultIPTrustWindowDays
	}
	if cfg.MaxIPsPerAsset <= 0 {
		cfg.MaxIPsPerAsset = DefaultMaxIPsPerAsset
	}
	return &AssetCorrelator{
		repo:   repo,
		logger: log.With("component", "asset-correlator"),
		config: cfg,
	}
}

// IPRecency reports when an IP address was last seen on an asset, from the
// asset_identifiers table. ok is false when nothing is recorded for the pair
// (an asset ingested before identifiers existed); the asset's own last_seen is
// used then.
type IPRecency func(assetID, ip string) (lastSeen time.Time, ok bool)

// CorrelateHost tries to find an existing host asset by IP addresses.
// tenantCfg overrides system defaults (pass nil to use system defaults).
func (c *AssetCorrelator) CorrelateHost(
	ctx context.Context,
	tenantID shared.ID,
	incomingName string,
	properties map[string]any,
	tenantCfg ...CorrelationConfig,
) (*CorrelationResult, error) {
	cfg := c.config
	if len(tenantCfg) > 0 {
		cfg = tenantCfg[0]
	}
	return c.CorrelateHostRecent(ctx, tenantID, incomingName, properties, cfg, nil)
}

// CorrelateHostRecent is CorrelateHost with per-IP recency. An IP match
// counts only when that IP was seen on the asset within the trust window
// (cfg.StaleAssetDays), and only when it is unambiguous: an IP that matches
// several assets matches none of them, and they are returned in Ambiguous for
// a duplicate review.
func (c *AssetCorrelator) CorrelateHostRecent(
	ctx context.Context,
	tenantID shared.ID,
	incomingName string,
	properties map[string]any,
	cfg CorrelationConfig,
	recency IPRecency,
) (*CorrelationResult, error) {
	if cfg.StaleAssetDays <= 0 {
		cfg.StaleAssetDays = DefaultIPTrustWindowDays
	}
	if cfg.MaxIPsPerAsset <= 0 {
		cfg.MaxIPsPerAsset = DefaultMaxIPsPerAsset
	}

	ips := ExtractAllIPs(properties, incomingName)

	// Guard: too many IPs → suspicious
	if len(ips) > cfg.MaxIPsPerAsset {
		c.logger.Warn("asset has too many IPs, skipping correlation",
			"name", logger.SanitizeValue(incomingName), "ip_count", len(ips))
		return &CorrelationResult{}, nil
	}

	// Guard: no IPs → can't correlate
	if len(ips) == 0 {
		return &CorrelationResult{}, nil
	}

	matched, err := c.repo.FindByIPs(ctx, tenantID, ips)
	if err != nil {
		return nil, err
	}

	// Collect unique matched assets, applying the trust window per IP.
	seen := make(map[string]*asset.Asset)
	for ip, assets := range matched {
		for _, a := range assets {
			if _, ok := seen[a.ID().String()]; ok {
				continue
			}
			lastSeen := a.LastSeen()
			if recency != nil {
				if t, ok := recency(a.ID().String(), ip); ok {
					lastSeen = t
				}
			}
			if !c.shouldCorrelateByIP(a, incomingName, cfg.StaleAssetDays, lastSeen) {
				continue
			}
			seen[a.ID().String()] = a
		}
	}

	if len(seen) == 0 {
		return &CorrelationResult{}, nil
	}

	// Convert to slice, most findings then oldest first
	assets := make([]*asset.Asset, 0, len(seen))
	for _, a := range seen {
		assets = append(assets, a)
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].FindingCount() != assets[j].FindingCount() {
			return assets[i].FindingCount() > assets[j].FindingCount()
		}
		return assets[i].CreatedAt().Before(assets[j].CreatedAt())
	})

	// An IP shared by several assets says nothing about which one this is.
	if len(assets) > 1 {
		return &CorrelationResult{Ambiguous: assets, CorrelationType: "ip"}, nil
	}

	primary := assets[0]
	result := &CorrelationResult{
		Matched:         primary,
		CorrelationType: "ip",
	}
	if shouldAdoptName(primary, incomingName, true) {
		result.ShouldRename = true
		result.NewName = incomingName
	}
	return result, nil
}

// shouldAdoptName decides whether an asset matched by IP takes the name the
// scanner reports now. A hostname is an attribute of the host, not its
// identity: when the matched host was renamed (x -> y, same IP) the inventory
// must follow, or every later report is merged into a record that still shows
// the old name and the new one is recorded nowhere.
//
//   - A better name always wins (IP -> hostname -> FQDN), as before.
//   - A different name of the same quality (x -> y, x.corp -> y.corp) wins
//     only when the IP match is unambiguous (one asset matched) and the name
//     is not one this asset already had. The alias check stops two sources
//     that name one IP differently from renaming the asset back and forth on
//     every scan; the price is that renaming a host back to an earlier name
//     is not followed.
//   - A worse name (FQDN -> short name, hostname -> IP) never wins.
func shouldAdoptName(existing *asset.Asset, incomingName string, unambiguous bool) bool {
	if incomingName == "" || incomingName == existing.Name() {
		return false
	}
	incoming, current := nameQuality(incomingName), nameQuality(existing.Name())
	if incoming > current {
		return true
	}
	if incoming < current || looksLikeIP(incomingName) {
		return false
	}
	return unambiguous && !hasAlias(existing, incomingName)
}

// hasAlias reports whether name is one of the asset's recorded former names.
func hasAlias(a *asset.Asset, name string) bool {
	switch v := a.Properties()["aliases"].(type) {
	case []string:
		for _, s := range v {
			if s == name {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == name {
				return true
			}
		}
	}
	return false
}

// shouldCorrelateByIP checks the trust window and type compatibility.
// lastSeen is when the matched IP was last seen on the asset.
func (c *AssetCorrelator) shouldCorrelateByIP(existing *asset.Asset, incomingName string, staleDays int, lastSeen time.Time) bool {
	// Same name → always match (existing behavior)
	if existing.Name() == incomingName {
		return true
	}

	// Only correlate host and ip_address types
	t := existing.Type()
	if t != asset.AssetTypeHost && t != asset.AssetTypeIPAddress {
		return false
	}

	// IP trust window: the asset must have been seen recently. Its IPs are
	// the ones it reported when last seen, so an asset outside the window may
	// have handed its address to another machine (DHCP).
	staleThreshold := time.Duration(staleDays) * 24 * time.Hour
	if time.Since(lastSeen) > staleThreshold {
		c.logger.Debug("skipping stale asset for IP correlation",
			"asset_id", existing.ID().String(),
			"name", existing.Name(),
			"last_seen", lastSeen,
			"stale_days", staleDays,
		)
		return false
	}

	return true
}

// nameQuality returns a score for how "good" an asset name is.
// Higher score = more stable, more human-readable identifier.
func nameQuality(name string) int {
	if name == "" {
		return 0
	}
	// IP address — least preferred (can change via DHCP)
	if looksLikeIP(name) {
		return 10
	}
	// Short hostname without domain (e.g., "server01")
	if !strings.Contains(name, ".") {
		return 30
	}
	// FQDN (e.g., "server01.corp.local")
	return 50
}

// looksLikeIP checks if a name looks like an IPv4 or IPv6 address.
func looksLikeIP(name string) bool {
	return net.ParseIP(name) != nil
}

// CorrelateByExternalID tries to find an existing asset by external_id.
// Used for cloud accounts, IAM users/roles.
func (c *AssetCorrelator) CorrelateByExternalID(
	ctx context.Context,
	tenantID shared.ID,
	externalID string,
) (*CorrelationResult, error) {
	if externalID == "" {
		return &CorrelationResult{}, nil
	}
	existing, err := c.repo.FindByExternalID(ctx, tenantID, externalID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return &CorrelationResult{}, nil
	}
	return &CorrelationResult{
		Matched:         existing,
		CorrelationType: "external_id",
	}, nil
}

// CorrelateCertificate tries to find an existing certificate by fingerprint.
func (c *AssetCorrelator) CorrelateCertificate(
	ctx context.Context,
	tenantID shared.ID,
	properties map[string]any,
) (*CorrelationResult, error) {
	fingerprint, _ := properties["fingerprint"].(string)
	if fingerprint == "" {
		return &CorrelationResult{}, nil
	}
	existing, err := c.repo.FindByPropertyValue(ctx, tenantID, "fingerprint", fingerprint)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return &CorrelationResult{}, nil
	}
	return &CorrelationResult{
		Matched:         existing,
		CorrelationType: "fingerprint",
	}, nil
}

// CorrelateRepository tries to find an existing repo when name has no host.
// E.g., "org/repo" might match "github.com/org/repo" if integration context known.
func (c *AssetCorrelator) CorrelateRepository(
	ctx context.Context,
	tenantID shared.ID,
	incomingName string,
	integrationHost string,
) (*CorrelationResult, error) {
	// If name already has a host (e.g., github.com/org/repo), no correlation needed
	if strings.Contains(incomingName, ".") {
		return &CorrelationResult{}, nil
	}

	// Strategy 1: Use integration host to build full name
	if integrationHost != "" {
		fullName := integrationHost + "/" + incomingName
		existing, err := c.repo.GetByName(ctx, tenantID, fullName)
		if err == nil && existing != nil {
			return &CorrelationResult{
				Matched:         existing,
				ShouldRename:    false, // Keep the more specific name
				CorrelationType: "repo_integration",
			}, nil
		}
	}

	// Strategy 2: Fuzzy match — find repos ending with "/org/repo"
	existing, err := c.repo.FindRepositoryByFullName(ctx, tenantID, incomingName)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return &CorrelationResult{
			Matched:         existing,
			CorrelationType: "repo_suffix",
		}, nil
	}

	return &CorrelationResult{}, nil
}

// ExtractAllIPs returns the IP addresses an asset is known by: its name when
// it is one, and the addresses its properties record (asset.IPAddresses,
// which reads ip_addresses and every synonym of it).
func ExtractAllIPs(properties map[string]any, assetName string) []string {
	ipSet := make(map[string]bool)
	if ip := net.ParseIP(assetName); ip != nil {
		ipSet[ip.String()] = true
	}
	for _, ip := range asset.IPAddresses(properties) {
		ipSet[ip] = true
	}
	return mapKeys(ipSet)
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
