package ingest

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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

// CorrelationConfig controls correlation behavior.
// System defaults are set at startup; per-tenant overrides can be passed
// via WithTenantOverrides() before calling CorrelateHost().
type CorrelationConfig struct {
	StaleAssetDays int // Don't merge if existing asset stale > N days (default: 30)
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

	// MergeTargets are additional assets that should be merged into Matched.
	// This happens when multiple existing assets match the same incoming data.
	MergeTargets []*asset.Asset

	// CorrelationType records how the match was found (for audit log).
	CorrelationType string // "ip", "hostname", "external_id", "fingerprint"
}

// NewAssetCorrelator creates a new correlator.
func NewAssetCorrelator(repo CorrelationRepo, log *logger.Logger, cfg CorrelationConfig) *AssetCorrelator {
	if cfg.StaleAssetDays <= 0 {
		cfg.StaleAssetDays = 30
	}
	if cfg.MaxIPsPerAsset <= 0 {
		cfg.MaxIPsPerAsset = 20
	}
	return &AssetCorrelator{
		repo:   repo,
		logger: log.With("component", "asset-correlator"),
		config: cfg,
	}
}

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

	ips := ExtractAllIPs(properties, incomingName)

	// Guard: too many IPs → suspicious
	if len(ips) > cfg.MaxIPsPerAsset {
		c.logger.Warn("asset has too many IPs, skipping correlation",
			"name", incomingName, "ip_count", len(ips))
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

	// Collect unique matched assets, applying staleness filter
	seen := make(map[string]*asset.Asset)
	for _, assets := range matched {
		for _, a := range assets {
			if _, ok := seen[a.ID().String()]; ok {
				continue
			}
			if !c.shouldCorrelateByIP(a, incomingName, cfg.StaleAssetDays) {
				continue
			}
			seen[a.ID().String()] = a
		}
	}

	if len(seen) == 0 {
		return &CorrelationResult{}, nil
	}

	// Convert to slice, pick primary (most findings, oldest)
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

	primary := assets[0]
	result := &CorrelationResult{
		Matched:         primary,
		CorrelationType: "ip",
	}

	// Should we rename? Only if incoming name is higher quality
	if nameQuality(incomingName) > nameQuality(primary.Name()) {
		result.ShouldRename = true
		result.NewName = incomingName
	}

	// Additional assets to merge (if multiple matched)
	if len(assets) > 1 {
		result.MergeTargets = assets[1:]
	}

	return result, nil
}

// shouldCorrelateByIP checks staleness and type compatibility.
func (c *AssetCorrelator) shouldCorrelateByIP(existing *asset.Asset, incomingName string, staleDays int) bool {
	// Same name → always match (existing behavior)
	if existing.Name() == incomingName {
		return true
	}

	// Only correlate host and ip_address types
	t := existing.Type()
	if t != asset.AssetTypeHost && t != asset.AssetTypeIPAddress {
		return false
	}

	// Staleness check
	staleThreshold := time.Duration(staleDays) * 24 * time.Hour
	if time.Since(existing.LastSeen()) > staleThreshold {
		c.logger.Debug("skipping stale asset for IP correlation",
			"asset_id", existing.ID().String(),
			"name", existing.Name(),
			"last_seen", existing.LastSeen(),
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

// ExtractAllIPs extracts all IP addresses from asset properties and name.
func ExtractAllIPs(properties map[string]any, assetName string) []string {
	ipSet := make(map[string]bool)

	// From name if it looks like IP
	if ip := net.ParseIP(assetName); ip != nil {
		ipSet[ip.String()] = true
	}

	if properties == nil {
		return mapKeys(ipSet)
	}

	// From properties.ip (legacy string)
	if ip, ok := properties["ip"].(string); ok && ip != "" {
		if parsed := net.ParseIP(ip); parsed != nil {
			ipSet[parsed.String()] = true
		}
	}

	// From properties.ip_address.address (structured)
	if ipAddr, ok := properties["ip_address"].(map[string]any); ok {
		if addr, ok := ipAddr["address"].(string); ok && addr != "" {
			if parsed := net.ParseIP(addr); parsed != nil {
				ipSet[parsed.String()] = true
			}
		}
	}

	// From properties.ip_addresses (array)
	if ips, ok := properties["ip_addresses"].([]any); ok {
		for _, v := range ips {
			if s, ok := v.(string); ok && s != "" {
				if parsed := net.ParseIP(s); parsed != nil {
					ipSet[parsed.String()] = true
				}
			}
		}
	}
	if ips, ok := properties["ip_addresses"].([]string); ok {
		for _, s := range ips {
			if parsed := net.ParseIP(s); parsed != nil {
				ipSet[parsed.String()] = true
			}
		}
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
