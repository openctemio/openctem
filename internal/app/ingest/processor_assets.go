package ingest

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
	"github.com/openctemio/ctis"
)

// AssetProcessor handles batch asset processing.
type AssetProcessor struct {
	repo           asset.Repository
	repoExtRepo    asset.RepositoryExtensionRepository
	relRepo        asset.RelationshipRepository
	correlator     *AssetCorrelator // RFC-001: IP-based correlation (nil = disabled)
	propsValidator *validator.PropertiesValidator
	logger         *logger.Logger
}

// NewAssetProcessor creates a new asset processor.
func NewAssetProcessor(repo asset.Repository, log *logger.Logger) *AssetProcessor {
	return &AssetProcessor{
		repo:           repo,
		propsValidator: validator.NewPropertiesValidator(),
		logger:         log.With("processor", "assets"),
	}
}

// SetRepositoryExtensionRepository sets the repository extension repository.
func (p *AssetProcessor) SetRepositoryExtensionRepository(repo asset.RepositoryExtensionRepository) {
	p.repoExtRepo = repo
}

// SetRelationshipRepository sets the asset relationship repository.
func (p *AssetProcessor) SetRelationshipRepository(repo asset.RelationshipRepository) {
	p.relRepo = repo
}

// SetCorrelator sets the asset correlator for IP-based deduplication.
// When nil (default), IP correlation is disabled.
func (p *AssetProcessor) SetCorrelator(c *AssetCorrelator) {
	p.correlator = c
}

// defaultCorrelationConfig returns the system default correlation config.
func (p *AssetProcessor) defaultCorrelationConfig() CorrelationConfig {
	if p.correlator != nil {
		return p.correlator.config
	}
	return CorrelationConfig{StaleAssetDays: 30, MaxIPsPerAsset: 20}
}

// ProcessBatch processes all assets using batch operations.
// Returns a map of asset ID (from CTIS) -> domain asset ID for finding association.
//
// If no explicit assets are provided in the report but findings exist,
// it will attempt to auto-create an asset using a priority chain:
//  1. BranchInfo.RepositoryURL in report metadata (most reliable for CI/CD)
//  2. Unique AssetValue from findings (if all findings reference same asset)
//  3. Scope.Name from report metadata
//  4. Inferred repository from file path patterns (e.g., github.com/org/repo)
//  5. Tool+ScanID fallback (ensures findings are never orphaned)
func (p *AssetProcessor) ProcessBatch(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	output *Output,
	tenantCfg *CorrelationConfig, // nil = use system defaults
) (map[string]shared.ID, error) {
	assetMap := make(map[string]shared.ID)

	p.logger.Debug("starting asset processing",
		"explicit_assets_count", len(report.Assets),
		"findings_count", len(report.Findings),
	)

	// If no explicit assets but there are findings, try to auto-create from metadata
	if len(report.Assets) == 0 {
		if len(report.Findings) > 0 {
			// Try to create asset from report metadata (BranchInfo)
			autoAsset := p.createAssetFromMetadata(report)
			if autoAsset != nil {
				report.Assets = append(report.Assets, *autoAsset)
				p.logger.Info("auto-created asset from report metadata",
					"asset_name", getAssetName(autoAsset),
					"asset_type", autoAsset.Type,
					"asset_id", autoAsset.ID,
				)
			} else {
				p.logger.Warn("failed to auto-create asset from metadata - all priority chains failed",
					"has_branch_info", report.Metadata.Branch != nil,
					"has_scope", report.Metadata.Scope != nil,
					"has_tool", report.Tool != nil,
					"findings_count", len(report.Findings),
				)
			}
		}

		// Still no assets after auto-creation attempt
		if len(report.Assets) == 0 {
			p.logger.Warn("no assets after auto-creation attempt - findings will be orphaned",
				"findings_count", len(report.Findings),
			)
			return assetMap, nil
		}
	}

	// Step 1: Collect all asset names for batch lookup
	// Names are normalized via NormalizeName inside getAssetName → NewAsset constructor
	names := make([]string, 0, len(report.Assets))
	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		name := getAssetName(ctisAsset)
		if name == "" {
			p.logger.Warn("asset has no name/value",
				"asset_index", i,
				"asset_id", ctisAsset.ID,
				"asset_type", ctisAsset.Type,
			)
			addError(output, fmt.Sprintf("asset %d: name/value is required", i))
			continue
		}
		// Normalize name before lookup so it matches existing normalized assets
		assetType := mapCTISAssetType(ctisAsset.Type)
		coreType, subType := asset.ResolveTypeAlias(assetType)
		name = asset.NormalizeName(name, coreType, subType)
		if name == "" {
			continue
		}
		names = append(names, name)
	}

	p.logger.Debug("collected asset names for lookup",
		"report_assets_count", len(report.Assets),
		"valid_names_count", len(names),
	)

	// Step 2: Batch lookup existing assets
	existingMap, err := p.repo.GetByNames(ctx, tenantID, names)
	if err != nil {
		return assetMap, fmt.Errorf("failed to batch lookup assets: %w", err)
	}

	p.logger.Debug("batch lookup complete",
		"total", len(names),
		"existing", len(existingMap),
	)

	// Step 3: Separate new vs existing assets
	// With IP correlation: if name doesn't match but IPs do, merge into existing.
	newAssets := make([]*asset.Asset, 0)
	updateAssets := make([]*asset.Asset, 0)

	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		name := getAssetName(ctisAsset)
		if name == "" {
			continue
		}

		// Normalize name (same as Step 1)
		assetType := mapCTISAssetType(ctisAsset.Type)
		coreType, subType := asset.ResolveTypeAlias(assetType)
		normalizedName := asset.NormalizeName(name, coreType, subType)
		if normalizedName == "" {
			continue
		}

		if existing, ok := existingMap[normalizedName]; ok {
			// Name match → merge (existing behavior)
			p.mergeCTISIntoAsset(existing, ctisAsset, report.Tool)
			updateAssets = append(updateAssets, existing)
			assetMap[ctisAsset.ID] = existing.ID()
		} else if p.correlator != nil && (coreType == asset.AssetTypeHost || coreType == asset.AssetTypeIPAddress) {
			// No name match for host/ip → try IP correlation (RFC-001 Phase 2)
			props := p.buildPropertiesFromCTIS(ctisAsset)
			var corrArgs []CorrelationConfig
			if tenantCfg != nil {
				corrArgs = append(corrArgs, *tenantCfg)
			}
			result, corrErr := p.correlator.CorrelateHost(ctx, tenantID, normalizedName, props, corrArgs...)
			if corrErr != nil {
				p.logger.Warn("IP correlation failed, creating new asset",
					"name", normalizedName, "error", corrErr)
			}

			if result != nil && result.Matched != nil {
				// IP match found → merge into existing
				existing := result.Matched
				p.mergeCTISIntoAsset(existing, ctisAsset, report.Tool)
				updateAssets = append(updateAssets, existing)
				assetMap[ctisAsset.ID] = existing.ID()

				if result.ShouldRename {
					if err := existing.UpdateName(result.NewName); err == nil {
						p.logger.Info("asset renamed via IP correlation",
							"id", existing.ID().String(),
							"old_name", existing.Name(),
							"new_name", result.NewName,
							"correlation_type", result.CorrelationType,
						)
					}
				}

				// Cache for later assets in same batch
				existingMap[normalizedName] = existing
			} else {
				// No correlation → create new
				newAsset, createErr := p.createAssetFromCTIS(tenantID, ctisAsset, report.Tool)
				if createErr != nil {
					addError(output, fmt.Sprintf("asset %s (%s): %v", ctisAsset.ID, normalizedName, createErr))
					continue
				}
				newAssets = append(newAssets, newAsset)
				assetMap[ctisAsset.ID] = newAsset.ID()
				existingMap[normalizedName] = newAsset
			}
		} else if p.correlator != nil {
			// Extended correlation for other asset types (RFC-001 Phase 3)
			var result *CorrelationResult
			var corrErr error

			switch coreType {
			case asset.AssetTypeRepository:
				result, corrErr = p.correlator.CorrelateRepository(ctx, tenantID, normalizedName, "")
			case asset.AssetTypeCloudAccount, asset.AssetTypeIdentity,
				asset.AssetTypeIAMUser, asset.AssetTypeIAMRole, asset.AssetTypeServiceAccount:
				// Try external_id from properties (account_id, arn, etc.)
				props := p.buildPropertiesFromCTIS(ctisAsset)
				externalID := ""
				if v, ok := props["account_id"].(string); ok && v != "" {
					externalID = v
				} else if v, ok := props["arn"].(string); ok && v != "" {
					externalID = v
				}
				result, corrErr = p.correlator.CorrelateByExternalID(ctx, tenantID, externalID)
			case asset.AssetTypeCertificate:
				props := p.buildPropertiesFromCTIS(ctisAsset)
				result, corrErr = p.correlator.CorrelateCertificate(ctx, tenantID, props)
			}

			if corrErr != nil {
				p.logger.Warn("extended correlation failed", "name", normalizedName, "type", coreType, "error", corrErr)
			}

			if result != nil && result.Matched != nil {
				existing := result.Matched
				p.mergeCTISIntoAsset(existing, ctisAsset, report.Tool)
				updateAssets = append(updateAssets, existing)
				assetMap[ctisAsset.ID] = existing.ID()
				existingMap[normalizedName] = existing
			} else {
				newAsset, createErr := p.createAssetFromCTIS(tenantID, ctisAsset, report.Tool)
				if createErr != nil {
					addError(output, fmt.Sprintf("asset %s (%s): %v", ctisAsset.ID, normalizedName, createErr))
					continue
				}
				newAssets = append(newAssets, newAsset)
				assetMap[ctisAsset.ID] = newAsset.ID()
				existingMap[normalizedName] = newAsset
			}
		} else {
			// Correlator disabled → create new
			newAsset, createErr := p.createAssetFromCTIS(tenantID, ctisAsset, report.Tool)
			if createErr != nil {
				addError(output, fmt.Sprintf("asset %s (%s): %v", ctisAsset.ID, normalizedName, createErr))
				continue
			}
			newAssets = append(newAssets, newAsset)
			assetMap[ctisAsset.ID] = newAsset.ID()
			existingMap[normalizedName] = newAsset
		}
	}

	// Step 4: Batch upsert assets
	if len(newAssets) > 0 || len(updateAssets) > 0 {
		allAssets := make([]*asset.Asset, 0, len(newAssets)+len(updateAssets))
		allAssets = append(allAssets, newAssets...)
		allAssets = append(allAssets, updateAssets...)
		created, updated, err := p.repo.UpsertBatch(ctx, allAssets)
		if err != nil {
			return assetMap, fmt.Errorf("failed to batch upsert assets: %w", err)
		}
		output.AssetsCreated = created
		output.AssetsUpdated = updated
	}

	// Step 5: Create/update repository extensions for repository assets
	if p.repoExtRepo != nil {
		for i := range report.Assets {
			ctisAsset := &report.Assets[i]
			if ctisAsset.Type != ctis.AssetTypeRepository {
				continue
			}

			name := getAssetName(ctisAsset)
			if name == "" {
				continue
			}

			domainAsset, ok := existingMap[name]
			if !ok {
				continue
			}

			// Create or update repository extension with web_url
			if err := p.ensureRepositoryExtension(ctx, domainAsset, name); err != nil {
				p.logger.Warn("failed to create repository extension",
					"asset_id", domainAsset.ID(),
					"asset_name", name,
					"error", err,
				)
			}
		}
	}

	// Step 5.5: Auto-create root domain assets for orphaned subdomains
	p.ensureRootDomainAssets(ctx, tenantID, report, existingMap, output)

	// Step 6: Create subdomain-to-domain relationships
	if p.relRepo != nil {
		p.createSubdomainRelationships(ctx, tenantID, report, existingMap)
	}

	// Step 7: Create resolves_to relationships for DNS records (domain/subdomain → IP)
	if p.relRepo != nil {
		p.createDNSResolvesToRelationships(ctx, tenantID, report, existingMap, output)
	}

	return assetMap, nil
}

// UpdateFindingCounts updates finding counts for processed assets.
func (p *AssetProcessor) UpdateFindingCounts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	return p.repo.UpdateFindingCounts(ctx, tenantID, assetIDs)
}

// ensureRepositoryExtension creates or updates the repository extension for a repository asset.
// It derives the web_url from the asset name (e.g., github.com/org/repo -> https://github.com/org/repo).
func (p *AssetProcessor) ensureRepositoryExtension(ctx context.Context, domainAsset *asset.Asset, assetName string) error {
	if p.repoExtRepo == nil {
		return nil
	}

	// Check if extension already exists
	existing, err := p.repoExtRepo.GetByAssetID(ctx, domainAsset.ID())
	if err == nil && existing != nil {
		// Extension exists, update web_url if empty
		if existing.WebURL() == "" {
			webURL := deriveWebURLFromAssetName(assetName)
			if webURL != "" {
				existing.SetWebURL(webURL)
				return p.repoExtRepo.Update(ctx, existing)
			}
		}
		return nil
	}

	// Create new repository extension
	repoExt, err := asset.NewRepositoryExtension(domainAsset.ID(), assetName, asset.RepoVisibilityPrivate)
	if err != nil {
		return fmt.Errorf("failed to create repository extension: %w", err)
	}

	// Derive and set web_url
	webURL := deriveWebURLFromAssetName(assetName)
	if webURL != "" {
		repoExt.SetWebURL(webURL)
	}

	// Set the full name as it might contain org/repo info
	repoExt.SetFullName(assetName)

	return p.repoExtRepo.Create(ctx, repoExt)
}

// ensureRootDomainAssets auto-creates root domain assets when subdomains reference
// a root_domain that doesn't exist yet. This ensures subdomain-to-domain relationships
// can always be created, even when only subdomains are ingested (e.g., from subfinder).
func (p *AssetProcessor) ensureRootDomainAssets(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	existingMap map[string]*asset.Asset,
	output *Output,
) {
	// Collect unique root domains that need to be created
	needed := make(map[string]bool)
	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		if ctisAsset.Type != ctis.AssetTypeSubdomain {
			continue
		}

		rootDomain, ok := ctisAsset.Properties["root_domain"].(string)
		if !ok || rootDomain == "" {
			continue
		}

		if !isValidDomainName(rootDomain) {
			continue
		}

		// Skip if root domain already exists in current batch
		if _, exists := existingMap[rootDomain]; exists {
			continue
		}

		needed[rootDomain] = true
	}

	if len(needed) == 0 {
		return
	}

	// Batch lookup in database for any that already exist outside this batch
	domainNames := make([]string, 0, len(needed))
	for name := range needed {
		domainNames = append(domainNames, name)
	}

	dbExisting, err := p.repo.GetByNames(ctx, tenantID, domainNames)
	if err != nil {
		p.logger.Warn("failed to lookup root domains in database", "error", err)
		return
	}

	// Add found domains to existingMap
	for name, a := range dbExisting {
		existingMap[name] = a
		delete(needed, name)
	}

	if len(needed) == 0 {
		return
	}

	// Create missing root domain assets
	newDomains := make([]*asset.Asset, 0, len(needed))
	for domainName := range needed {
		domainAsset, err := asset.NewAsset(domainName, asset.AssetTypeDomain, asset.CriticalityMedium)
		if err != nil {
			p.logger.Warn("failed to create root domain asset entity",
				"domain", domainName,
				"error", err,
			)
			continue
		}

		domainAsset.SetTenantID(tenantID)
		domainAsset.UpdateDescription("Root domain auto-created from subdomain discovery")

		now := time.Now()
		domainAsset.SetDiscoveryInfo(asset.DiscoverySourceDNS, "subdomain_enumeration", &now)

		metadata := asset.BuildDomainMetadata(domainName, asset.DiscoverySourceDNS)
		domainAsset.SetProperties(metadata)

		newDomains = append(newDomains, domainAsset)
		existingMap[domainName] = domainAsset
	}

	if len(newDomains) == 0 {
		return
	}

	created, _, err := p.repo.UpsertBatch(ctx, newDomains)
	if err != nil {
		p.logger.Warn("failed to batch create root domain assets",
			"count", len(newDomains),
			"error", err,
		)
		// Remove from existingMap since creation failed
		for _, a := range newDomains {
			delete(existingMap, a.Name())
		}
		return
	}

	output.AssetsCreated += created
	p.logger.Info("auto-created root domain assets for orphaned subdomains",
		"created", created,
		"domains", domainNames,
	)
}

// createSubdomainRelationships creates member_of relationships between subdomain and parent domain assets.
// This links subdomains to their parent domains in the asset relationship graph.
// Uses batch INSERT...ON CONFLICT DO NOTHING for efficiency (1 query instead of 2N).
func (p *AssetProcessor) createSubdomainRelationships(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	existingMap map[string]*asset.Asset,
) {
	// Collect all relationships to create
	rels := make([]*asset.Relationship, 0)

	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		if ctisAsset.Type != ctis.AssetTypeSubdomain {
			continue
		}

		// Get root_domain from properties (set by recon converter)
		rootDomain, ok := ctisAsset.Properties["root_domain"].(string)
		if !ok || rootDomain == "" {
			continue
		}

		// Validate domain format
		if !isValidDomainName(rootDomain) {
			p.logger.Warn("invalid root_domain format, skipping relationship",
				"root_domain", rootDomain,
			)
			continue
		}

		subdomainName := getAssetName(ctisAsset)
		if subdomainName == "" {
			continue
		}

		// Find both assets in the existing map
		subdomainAsset, subOk := existingMap[subdomainName]
		parentAsset, parentOk := existingMap[rootDomain]
		if !subOk || !parentOk {
			continue
		}

		// Create `contains` relationship: parent_domain → subdomain.
		// We use the canonical hierarchy direction (source = parent,
		// target = child) — `member_of` was removed from the registry
		// in favour of a single hierarchy direction. See
		// configs/relationship-types.yaml for the design rationale.
		rel, err := asset.NewRelationship(tenantID, parentAsset.ID(), subdomainAsset.ID(), asset.RelTypeContains)
		if err != nil {
			p.logger.Warn("failed to create subdomain relationship entity",
				"subdomain", subdomainName,
				"domain", rootDomain,
				"error", err,
			)
			continue
		}

		rel.SetDescription(fmt.Sprintf("Domain %s contains subdomain %s", rootDomain, subdomainName))
		_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)

		rels = append(rels, rel)
	}

	if len(rels) == 0 {
		return
	}

	// Batch insert all relationships, skipping duplicates via ON CONFLICT DO NOTHING
	created, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		p.logger.Warn("failed to batch create subdomain relationships",
			"total", len(rels),
			"error", err,
		)
		return
	}

	if created > 0 {
		p.logger.Info("created subdomain relationships",
			"created", created,
			"skipped", len(rels)-created,
		)
	}
}

// createDNSResolvesToRelationships creates resolves_to relationships between domain/subdomain
// assets and their resolved IP addresses. If IP assets don't exist yet, they are auto-created.
// This maps the DNS resolution graph for attack surface analysis.
func (p *AssetProcessor) createDNSResolvesToRelationships(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	existingMap map[string]*asset.Asset,
	output *Output,
) {
	// Collect domain→IP mappings from report assets
	type dnsMapping struct {
		domainName string
		ip         string
	}
	mappings := make([]dnsMapping, 0)
	ipSet := make(map[string]bool)

	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		if ctisAsset.Type != ctis.AssetTypeDomain && ctisAsset.Type != ctis.AssetTypeSubdomain {
			continue
		}

		domainName := getAssetName(ctisAsset)
		if domainName == "" {
			continue
		}

		// Check if domain exists in our map
		if _, ok := existingMap[domainName]; !ok {
			continue
		}

		// Extract resolved IPs from properties
		ips, ok := ctisAsset.Properties["resolved_ips"].([]string)
		if !ok {
			// Try []any (JSON unmarshaling produces this)
			if ifaces, ok := ctisAsset.Properties["resolved_ips"].([]any); ok {
				ips = make([]string, 0, len(ifaces))
				for _, iface := range ifaces {
					if s, ok := iface.(string); ok && s != "" {
						ips = append(ips, s)
					}
				}
			}
		}

		for _, ip := range ips {
			if ip == "" || !isValidIP(ip) {
				continue
			}
			mappings = append(mappings, dnsMapping{domainName: domainName, ip: ip})
			ipSet[ip] = true
		}
	}

	if len(mappings) == 0 {
		return
	}

	// Ensure IP assets exist
	ipNames := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipNames = append(ipNames, ip)
	}

	dbIPs, err := p.repo.GetByNames(ctx, tenantID, ipNames)
	if err != nil {
		p.logger.Warn("failed to lookup IP assets", "error", err)
		return
	}
	for name, a := range dbIPs {
		existingMap[name] = a
	}

	// Create missing IP assets
	newIPs := make([]*asset.Asset, 0)
	for ip := range ipSet {
		if _, exists := existingMap[ip]; exists {
			continue
		}

		ipAsset, err := asset.NewAsset(ip, asset.AssetTypeIPAddress, asset.CriticalityLow)
		if err != nil {
			continue
		}
		ipAsset.SetTenantID(tenantID)
		ipAsset.UpdateDescription("IP address auto-created from DNS resolution")

		now := time.Now()
		ipAsset.SetDiscoveryInfo(asset.DiscoverySourceDNS, "dns_resolution", &now)

		newIPs = append(newIPs, ipAsset)
		existingMap[ip] = ipAsset
	}

	if len(newIPs) > 0 {
		created, _, err := p.repo.UpsertBatch(ctx, newIPs)
		if err != nil {
			p.logger.Warn("failed to create IP assets from DNS resolution", "error", err)
			for _, a := range newIPs {
				delete(existingMap, a.Name())
			}
			return
		}
		output.AssetsCreated += created
	}

	// Create resolves_to relationships
	rels := make([]*asset.Relationship, 0, len(mappings))
	for _, m := range mappings {
		domainAsset, dOk := existingMap[m.domainName]
		ipAsset, iOk := existingMap[m.ip]
		if !dOk || !iOk {
			continue
		}

		rel, err := asset.NewRelationship(tenantID, domainAsset.ID(), ipAsset.ID(), asset.RelTypeResolvesTo)
		if err != nil {
			continue
		}
		rel.SetDescription(fmt.Sprintf("%s resolves to %s", m.domainName, m.ip))
		_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)
		rels = append(rels, rel)
	}

	if len(rels) == 0 {
		return
	}

	created, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		p.logger.Warn("failed to create DNS resolves_to relationships", "error", err)
		return
	}

	if created > 0 {
		p.logger.Info("created DNS resolves_to relationships",
			"created", created,
			"skipped", len(rels)-created,
		)
	}
}

// isValidIP performs basic IP address validation (IPv4 and IPv6).
func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	// Simple validation: must contain dots (IPv4) or colons (IPv6)
	return strings.Contains(ip, ".") || strings.Contains(ip, ":")
}

// isValidDomainName validates a basic domain name format.
func isValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		// Labels cannot start or end with hyphen
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}
	return true
}

// deriveWebURLFromAssetName derives the web URL from an asset name.
// Supports formats like:
//   - github.com/org/repo -> https://github.com/org/repo
//   - gitlab.com/org/repo -> https://gitlab.com/org/repo
//   - bitbucket.org/org/repo -> https://bitbucket.org/org/repo
//   - https://github.com/org/repo -> https://github.com/org/repo (already a URL)
func deriveWebURLFromAssetName(name string) string {
	// If already a full URL, return as-is
	if strings.HasPrefix(name, "https://") || strings.HasPrefix(name, "http://") {
		return name
	}

	// Check for known git hosting patterns
	gitHostPattern := regexp.MustCompile(`^(github\.com|gitlab\.com|bitbucket\.org)/([^/]+)/([^/]+)`)
	if matches := gitHostPattern.FindStringSubmatch(name); len(matches) >= 4 {
		host := matches[1]
		org := matches[2]
		repo := matches[3]
		return fmt.Sprintf("https://%s/%s/%s", host, org, repo)
	}

	// Check for self-hosted patterns like gitlab.company.com/org/repo
	selfHostedPattern := regexp.MustCompile(`^(gitlab\.[a-zA-Z0-9.-]+|github\.[a-zA-Z0-9.-]+)/([^/]+)/([^/]+)`)
	if matches := selfHostedPattern.FindStringSubmatch(name); len(matches) >= 4 {
		host := matches[1]
		org := matches[2]
		repo := matches[3]
		return fmt.Sprintf("https://%s/%s/%s", host, org, repo)
	}

	return ""
}

// getAssetName extracts the name from a CTIS asset.
func getAssetName(ctisAsset *ctis.Asset) string {
	if ctisAsset.Name != "" {
		return ctisAsset.Name
	}
	return ctisAsset.Value
}

// createAssetFromMetadata creates a CTIS asset from report metadata using a priority chain.
// This ensures findings are never orphaned due to missing asset context.
//
// Priority chain:
//  1. BranchInfo.RepositoryURL - Most reliable for CI/CD scans
//  2. Unique AssetValue from findings - If all findings share same asset
//  3. Scope.Name from metadata - Explicit scan scope
//  4. Repository inferred from file paths - Pattern matching (github.com/org/repo)
//  5. Tool+ScanID fallback - Uses tool name with scan ID
//  6. Emergency fallback - Uses scan_id alone or generates UUID (ensures findings are NEVER orphaned)
//
// This function should NEVER return nil when there are findings to process.
func (p *AssetProcessor) createAssetFromMetadata(report *ctis.Report) *ctis.Asset {
	// Priority 1: BranchInfo.RepositoryURL (most reliable for CI/CD scans)
	if asset := p.createAssetFromBranchInfo(report); asset != nil {
		return asset
	}

	// Priority 2: Unique AssetValue from ALL findings (not just first)
	if asset := p.createAssetFromFindingValues(report); asset != nil {
		return asset
	}

	// Priority 3: Scope information
	if asset := p.createAssetFromScope(report); asset != nil {
		return asset
	}

	// Priority 4: Infer repository from file path patterns
	if asset := p.createAssetFromPathInference(report); asset != nil {
		return asset
	}

	// Priority 5: Tool+ScanID fallback (uses tool name with scan ID)
	if asset := p.createAssetFromToolFallback(report); asset != nil {
		return asset
	}

	// Priority 6: Emergency fallback - ensures findings are NEVER orphaned
	// Uses scan_id if available, otherwise generates a timestamp-based ID
	return p.createAssetFromEmergencyFallback(report)
}

// createAssetFromBranchInfo creates asset from BranchInfo.RepositoryURL.
// This is the most reliable source for CI/CD scans.
func (p *AssetProcessor) createAssetFromBranchInfo(report *ctis.Report) *ctis.Asset {
	if report.Metadata.Branch == nil || report.Metadata.Branch.RepositoryURL == "" {
		return nil
	}

	repoURL := report.Metadata.Branch.RepositoryURL
	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        ctis.AssetTypeRepository,
		Value:       repoURL,
		Name:        repoURL,
		Criticality: ctis.CriticalityHigh,
		Properties: ctis.Properties{
			"auto_created":   true,
			"source":         "branch_info",
			"commit_sha":     report.Metadata.Branch.CommitSHA,
			"branch":         report.Metadata.Branch.Name,
			"default_branch": report.Metadata.Branch.IsDefaultBranch,
		},
	}
}

// createAssetFromFindingValues creates asset from findings' AssetValue.
// Only creates asset if ALL findings with AssetValue reference the SAME asset.
// This prevents incorrect asset creation when findings span multiple repos.
func (p *AssetProcessor) createAssetFromFindingValues(report *ctis.Report) *ctis.Asset {
	// Collect unique asset values from ALL findings
	type assetInfo struct {
		assetType ctis.AssetType
		count     int
	}
	assetSet := make(map[string]*assetInfo)

	for _, finding := range report.Findings {
		if finding.AssetValue == "" {
			continue
		}
		if info, exists := assetSet[finding.AssetValue]; exists {
			info.count++
		} else {
			assetType := finding.AssetType
			if assetType == "" {
				assetType = ctis.AssetTypeRepository
			}
			assetSet[finding.AssetValue] = &assetInfo{assetType: assetType, count: 1}
		}
	}

	// Only auto-create if exactly 1 unique asset value
	// Multiple different values = require explicit assets (safer)
	if len(assetSet) != 1 {
		if len(assetSet) > 1 && p.logger != nil {
			p.logger.Debug("multiple asset values found in findings, skipping auto-creation",
				"count", len(assetSet),
			)
		}
		return nil
	}

	for value, info := range assetSet {
		// SECURITY: Sanitize user-provided asset value
		sanitizedValue := sanitizeAssetName(value)
		if sanitizedValue == "" {
			if p.logger != nil {
				p.logger.Warn("asset value sanitized to empty, skipping",
					"original_value", value,
				)
			}
			return nil
		}

		if p.logger != nil {
			p.logger.Debug("creating asset from finding values",
				"value", sanitizedValue,
				"type", info.assetType,
				"finding_count", info.count,
			)
		}
		return &ctis.Asset{
			ID:          "auto-asset-1",
			Type:        info.assetType,
			Value:       sanitizedValue,
			Name:        sanitizedValue,
			Criticality: ctis.CriticalityHigh,
			Properties: ctis.Properties{
				"auto_created":  true,
				"source":        "finding_asset_value",
				"finding_count": info.count,
			},
		}
	}

	return nil
}

// createAssetFromScope creates asset from report metadata Scope.
func (p *AssetProcessor) createAssetFromScope(report *ctis.Report) *ctis.Asset {
	if report.Metadata.Scope == nil || report.Metadata.Scope.Name == "" {
		return nil
	}

	scopeType := ctis.AssetTypeUnclassified
	switch report.Metadata.Scope.Type {
	case "repository":
		scopeType = ctis.AssetTypeRepository
	case "domain":
		scopeType = ctis.AssetTypeDomain
	case "ip_address":
		scopeType = ctis.AssetTypeIPAddress
	case "container":
		scopeType = ctis.AssetTypeContainer
	case "cloud_account":
		scopeType = ctis.AssetTypeCloudAccount
	}

	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        scopeType,
		Value:       report.Metadata.Scope.Name,
		Name:        report.Metadata.Scope.Name,
		Criticality: ctis.CriticalityMedium,
		Properties: ctis.Properties{
			"auto_created": true,
			"source":       "scope",
			"scope_type":   report.Metadata.Scope.Type,
		},
	}
}

// createAssetFromPathInference infers repository from file path patterns.
// Supports patterns like:
//   - github.com/org/repo/path/to/file.go
//   - gitlab.com/org/repo/path/to/file.go
//   - bitbucket.org/org/repo/path/to/file.go
//
// Also detects common project root patterns when paths share a common prefix.
func (p *AssetProcessor) createAssetFromPathInference(report *ctis.Report) *ctis.Asset {
	if len(report.Findings) == 0 {
		return nil
	}

	// Collect all file paths from findings
	var paths []string
	for _, finding := range report.Findings {
		if finding.Location != nil && finding.Location.Path != "" {
			paths = append(paths, finding.Location.Path)
		}
	}

	if len(paths) == 0 {
		return nil
	}

	// Pattern 1: Check for Git hosting URL patterns in paths
	// e.g., github.com/org/repo/... or file:///github.com/org/repo/...
	// SECURITY: Only allow known git hosts to prevent domain spoofing
	gitHostPattern := regexp.MustCompile(`(github\.com|gitlab\.com|bitbucket\.org)/([^/]+)/([^/]+)`)
	for _, path := range paths {
		if matches := gitHostPattern.FindStringSubmatch(path); len(matches) >= 4 {
			host := matches[1]
			org := matches[2]
			repo := matches[3]

			// SECURITY: Validate host is known git provider
			if !isValidGitHost(host) {
				continue
			}

			// SECURITY: Sanitize org and repo names
			org = sanitizeAssetName(org)
			repo = sanitizeAssetName(repo)
			if org == "" || repo == "" {
				continue
			}

			repoURL := fmt.Sprintf("https://%s/%s/%s", host, org, repo)

			if p.logger != nil {
				p.logger.Debug("inferred repository from path pattern",
					"repo_url", repoURL,
					"source_path", path,
				)
			}
			return &ctis.Asset{
				ID:          "auto-asset-1",
				Type:        ctis.AssetTypeRepository,
				Value:       repoURL,
				Name:        repoURL,
				Criticality: ctis.CriticalityHigh,
				Properties: ctis.Properties{
					"auto_created": true,
					"source":       "path_inference",
					"pattern":      "git_host_url",
				},
			}
		}
	}

	// Pattern 2: Find common path prefix (project root)
	// If all paths share a common directory prefix, use it as project identifier
	if len(paths) >= 2 {
		commonPrefix := findCommonPathPrefix(paths)
		if commonPrefix != "" && len(commonPrefix) > 3 {
			// Clean up the prefix
			projectName := filepath.Base(commonPrefix)
			if projectName == "" || projectName == "." || projectName == "/" {
				projectName = commonPrefix
			}
			// Only use if it looks like a meaningful project name
			if len(projectName) >= 2 && !strings.HasPrefix(projectName, ".") {
				// SECURITY: Sanitize project name
				projectName = sanitizeAssetName(projectName)
				if projectName == "" {
					return nil
				}

				// SECURITY: Sanitize common_prefix to avoid path disclosure
				sanitizedPrefix := sanitizePathForProperty(commonPrefix)

				if p.logger != nil {
					p.logger.Debug("inferred project from common path prefix",
						"project_name", projectName,
						"common_prefix", sanitizedPrefix,
						"path_count", len(paths),
					)
				}
				return &ctis.Asset{
					ID:          "auto-asset-1",
					Type:        ctis.AssetTypeRepository,
					Value:       projectName,
					Name:        projectName,
					Criticality: ctis.CriticalityMedium,
					Properties: ctis.Properties{
						"auto_created":  true,
						"source":        "path_inference",
						"pattern":       "common_prefix",
						"common_prefix": sanitizedPrefix, // SECURITY: Sanitized path
					},
				}
			}
		}
	}

	return nil
}

// createAssetFromToolFallback creates a pseudo-asset from tool name and scan ID.
// This is the last resort to ensure findings are never orphaned.
func (p *AssetProcessor) createAssetFromToolFallback(report *ctis.Report) *ctis.Asset {
	// Need at least tool name to create meaningful fallback
	if report.Tool == nil || report.Tool.Name == "" {
		return nil
	}

	toolName := report.Tool.Name
	scanID := report.Metadata.ID
	if scanID == "" {
		scanID = UnknownValue
	}

	// Create a meaningful identifier
	assetName := fmt.Sprintf("scan:%s:%s", toolName, scanID)

	if p.logger != nil {
		p.logger.Info("creating fallback asset from tool+scan_id",
			"tool_name", toolName,
			"scan_id", scanID,
			"asset_name", assetName,
		)
	}

	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        ctis.AssetTypeUnclassified,
		Value:       assetName,
		Name:        assetName,
		Criticality: ctis.CriticalityMedium,
		Properties: ctis.Properties{
			"auto_created": true,
			"source":       "tool_fallback",
			"tool_name":    toolName,
			"scan_id":      scanID,
		},
	}
}

// createAssetFromEmergencyFallback creates a pseudo-asset when all other methods fail.
// This is the absolute last resort to ensure findings are NEVER orphaned.
// Uses scan_id if available, otherwise generates a timestamp-based ID.
func (p *AssetProcessor) createAssetFromEmergencyFallback(report *ctis.Report) *ctis.Asset {
	// Try to use scan ID
	scanID := report.Metadata.ID
	if scanID == "" {
		// Generate a timestamp-based ID as last resort
		scanID = fmt.Sprintf("ingest-%d", time.Now().UnixNano())
	}

	// Try to extract source type for more meaningful naming
	sourceType := report.Metadata.SourceType
	if sourceType == "" {
		sourceType = "unknown"
	}

	assetName := fmt.Sprintf("scan:%s:%s", sourceType, scanID)

	if p.logger != nil {
		p.logger.Warn("creating emergency fallback asset - report lacks metadata",
			"scan_id", scanID,
			"source_type", sourceType,
			"asset_name", assetName,
			"findings_count", len(report.Findings),
		)
	}

	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        ctis.AssetTypeUnclassified,
		Value:       assetName,
		Name:        assetName,
		Criticality: ctis.CriticalityLow, // Low criticality since we have no context
		Properties: ctis.Properties{
			"auto_created":   true,
			"source":         "emergency_fallback",
			"scan_id":        scanID,
			"source_type":    sourceType,
			"findings_count": len(report.Findings),
		},
	}
}

// findCommonPathPrefix finds the longest common directory prefix among paths.
func findCommonPathPrefix(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) == 1 {
		return filepath.Dir(paths[0])
	}

	// Start with first path's directory
	prefix := filepath.Dir(paths[0])

	for _, path := range paths[1:] {
		pathDir := filepath.Dir(path)
		// Find common prefix between current prefix and this path
		for !strings.HasPrefix(pathDir, prefix) && prefix != "" && prefix != "." && prefix != "/" {
			prefix = filepath.Dir(prefix)
		}
		if prefix == "" || prefix == "." || prefix == "/" {
			return ""
		}
	}

	return prefix
}

// createAssetFromCTIS creates a new domain Asset from a CTIS Asset.
func (p *AssetProcessor) createAssetFromCTIS(
	tenantID shared.ID,
	ctisAsset *ctis.Asset,
	tool *ctis.Tool,
) (*asset.Asset, error) {
	rawType := mapCTISAssetType(ctisAsset.Type)
	// Resolve type aliases: e.g., "firewall" → type=network, sub_type=firewall
	coreType, subType := asset.ResolveTypeAlias(rawType)
	criticality := mapCTISCriticality(ctisAsset.Criticality)

	name := getAssetName(ctisAsset)
	if name == "" {
		return nil, fmt.Errorf("asset name/value is required")
	}

	// Validate name length - log if truncated
	const maxNameLength = 1024
	if len(name) > maxNameLength {
		p.logger.Warn("asset name truncated",
			"original_length", len(name),
			"max_length", maxNameLength,
			"asset_id", ctisAsset.ID,
		)
		name = name[:maxNameLength]
	}

	newAsset, err := asset.NewAsset(name, coreType, criticality)
	if err != nil {
		return nil, err
	}

	// Set sub_type from TypeAliases or from properties
	if subType != "" {
		newAsset.SetSubType(subType)
	}

	newAsset.SetTenantID(tenantID)

	// Set description (with length limit) - log if truncated
	const maxDescLength = 4096
	if ctisAsset.Description != "" {
		desc := ctisAsset.Description
		if len(desc) > maxDescLength {
			p.logger.Warn("asset description truncated",
				"original_length", len(desc),
				"max_length", maxDescLength,
				"asset_id", ctisAsset.ID,
			)
			desc = desc[:maxDescLength]
		}
		newAsset.UpdateDescription(desc)
	}

	// Set tags (with limit) - log if truncated
	tags := ctisAsset.Tags
	if len(tags) > MaxTagsPerAsset {
		p.logger.Warn("asset tags truncated",
			"original_count", len(tags),
			"max_count", MaxTagsPerAsset,
			"asset_id", ctisAsset.ID,
		)
		tags = tags[:MaxTagsPerAsset]
	}
	for _, tag := range tags {
		newAsset.AddTag(tag)
	}

	// Promote sub_type from properties if not already set via TypeAliases
	if newAsset.SubType() == "" {
		if st, ok := ctisAsset.Properties["sub_type"].(string); ok && st != "" {
			newAsset.SetSubType(st)
			delete(ctisAsset.Properties, "sub_type")
		}
	}

	// Set discovery info
	discoverySource := "agent"
	discoveryTool := ""
	if tool != nil {
		discoveryTool = tool.Name
	}
	if source, ok := ctisAsset.Properties["discovery_source"].(string); ok {
		discoverySource = source
	}
	if toolName, ok := ctisAsset.Properties["discovery_tool"].(string); ok {
		discoveryTool = toolName
	}

	discoveredAt := ctisAsset.DiscoveredAt
	if discoveredAt == nil {
		now := time.Now()
		discoveredAt = &now
	}
	newAsset.SetDiscoveryInfo(discoverySource, discoveryTool, discoveredAt)

	// Set owner reference from external source
	ownerRef := p.extractOwnerRef(ctisAsset)
	if ownerRef != "" {
		newAsset.SetOwnerRef(ownerRef)
	}

	// Build and set properties (with validation)
	properties := p.buildPropertiesFromCTIS(ctisAsset)
	newAsset.SetProperties(properties)

	return newAsset, nil
}

// mergeCTISIntoAsset merges CTIS data into an existing asset.
func (p *AssetProcessor) mergeCTISIntoAsset(existing *asset.Asset, ctisAsset *ctis.Asset, tool *ctis.Tool) {
	// Mark as seen
	existing.MarkSeen()

	// Update owner ref if provided and not already set
	if existing.OwnerRef() == "" {
		if ownerRef := p.extractOwnerRef(ctisAsset); ownerRef != "" {
			existing.SetOwnerRef(ownerRef)
		}
	}

	// Merge tags
	for _, tag := range ctisAsset.Tags {
		existing.AddTag(tag)
	}

	// Merge properties using deep merge
	existingProps := existing.Properties()
	newProps := p.buildPropertiesFromCTIS(ctisAsset)
	mergedProps := mergePropertiesDeep(existingProps, newProps)
	existing.SetProperties(mergedProps)

	// Promote sub_type if existing asset doesn't have one
	if existing.SubType() == "" {
		// Try explicit sub_type from CTIS properties
		if st, ok := ctisAsset.Properties["sub_type"].(string); ok && st != "" {
			existing.SetSubType(st)
		} else if ctisAsset.Type != "" {
			// Try TypeAliases inference (e.g., "firewall" → network + firewall)
			if _, subType := asset.ResolveTypeAlias(asset.AssetType(ctisAsset.Type)); subType != "" {
				existing.SetSubType(subType)
			}
		}
	}

	// Update discovery tool if not set
	if existing.DiscoveryTool() == "" && tool != nil {
		existing.SetDiscoveryTool(tool.Name)
	}
}

// buildPropertiesFromCTIS builds the properties JSONB from CTIS Asset.
func (p *AssetProcessor) buildPropertiesFromCTIS(ctisAsset *ctis.Asset) map[string]any {
	props := make(map[string]any)

	// Copy CTIS properties (with validation)
	propCount := 0
	for k, v := range ctisAsset.Properties {
		if propCount >= MaxPropertiesPerAsset {
			break
		}

		// Skip discovery fields (handled separately)
		if k == "discovery_source" || k == "discovery_tool" {
			continue
		}

		// Validate key length
		if len(k) > 100 {
			continue
		}

		props[k] = v
		propCount++
	}

	// Add technical details based on asset type
	if ctisAsset.Technical != nil {
		if ctisAsset.Technical.Domain != nil {
			props["domain"] = buildDomainProperties(ctisAsset.Technical.Domain)
		}
		if ctisAsset.Technical.IPAddress != nil {
			props["ip_address"] = buildIPAddressProperties(ctisAsset.Technical.IPAddress)
		}
		if ctisAsset.Technical.Service != nil {
			props["service"] = buildServiceProperties(ctisAsset.Technical.Service)
		}
		if ctisAsset.Technical.Certificate != nil {
			props["certificate"] = buildCertificateProperties(ctisAsset.Technical.Certificate)
		}
	}

	// Normalize IP storage for host assets:
	// - Convert properties.ip (string) → properties.ip_addresses (array)
	// - Extract IP from asset value/name if host type
	// - Extract hostname from ip_address.hostname into top-level hostname
	if ctisAsset.Type == ctis.AssetTypeHost || ctisAsset.Type == "host" {
		normalizeHostIPProperties(props, getAssetName(ctisAsset))
	}

	// Validate properties based on asset type
	if errs := p.propsValidator.ValidateProperties(string(ctisAsset.Type), props); errs != nil {
		p.logger.Warn("properties validation errors",
			"asset_type", ctisAsset.Type,
			"asset_value", ctisAsset.Value,
			"errors", errs.Error(),
		)
	}

	return props
}

// extractOwnerRef extracts owner reference from CTIS asset.
// Checks multiple sources: compliance.regulatory_owner, technical.repository.owner,
// properties.owner, properties.contact.
func (p *AssetProcessor) extractOwnerRef(ctisAsset *ctis.Asset) string {
	// 1. Compliance regulatory owner (highest priority)
	if ctisAsset.Compliance != nil && ctisAsset.Compliance.RegulatoryOwner != "" {
		return ctisAsset.Compliance.RegulatoryOwner
	}

	// 2. Repository owner (GitHub/GitLab org)
	if ctisAsset.Technical != nil && ctisAsset.Technical.Repository != nil && ctisAsset.Technical.Repository.Owner != "" {
		return ctisAsset.Technical.Repository.Owner
	}

	// 3. Properties (custom fields from scanner)
	if owner, ok := ctisAsset.Properties["owner"].(string); ok && owner != "" {
		return owner
	}
	if contact, ok := ctisAsset.Properties["contact"].(string); ok && contact != "" {
		return contact
	}
	if responsible, ok := ctisAsset.Properties["responsible"].(string); ok && responsible != "" {
		return responsible
	}

	return ""
}

// normalizeHostIPProperties standardizes IP storage for host assets.
// Ensures all IPs are in `ip_addresses` (array), removes legacy `ip` (string).
// Promotes ip_address.hostname to top-level `hostname`.
func normalizeHostIPProperties(props map[string]any, assetName string) {
	// Collect all known IPs into a set
	ipSet := make(map[string]bool)

	// From legacy properties.ip (string)
	if ip, ok := props["ip"].(string); ok && ip != "" {
		ipSet[ip] = true
		delete(props, "ip") // Remove legacy key
	}

	// From existing ip_addresses array
	if ips, ok := props["ip_addresses"].([]any); ok {
		for _, v := range ips {
			if s, ok := v.(string); ok && s != "" {
				ipSet[s] = true
			}
		}
	}
	if ips, ok := props["ip_addresses"].([]string); ok {
		for _, s := range ips {
			if s != "" {
				ipSet[s] = true
			}
		}
	}

	// From ip_address technical data (structured object)
	if ipAddr, ok := props["ip_address"].(map[string]any); ok {
		if addr, ok := ipAddr["address"].(string); ok && addr != "" {
			ipSet[addr] = true
		}
		// Promote hostname to top-level if not already set
		if hostname, ok := ipAddr["hostname"].(string); ok && hostname != "" {
			if _, exists := props["hostname"]; !exists {
				props["hostname"] = hostname
			}
		}
	}

	// From asset name if it looks like an IP
	if looksLikeIPv4(assetName) {
		ipSet[assetName] = true
	}

	// Write back as standardized array
	if len(ipSet) > 0 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		props["ip_addresses"] = ips
	}
}

// looksLikeIPv4 returns true if s matches basic IPv4 pattern.
func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
