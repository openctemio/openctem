package threatmodel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/openctemio/api/internal/app/attack"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// maxThreats caps the total enumerated threats per model so a large graph ×
// many profiles cannot produce an unbounded write. Highest-scoring threats are
// kept; truncation is logged.
const maxThreats = 5000

// ExposureChainProvider yields the tenant's exposure chains (public entry point
// → KEV/critical target). Implemented by *attack.SurfaceService.
type ExposureChainProvider interface {
	GetExposureChains(ctx context.Context, tenantID shared.ID) (*attack.ExposureChainResult, error)
}

// Service generates and reads threat models. It composes the exposure-chain
// engine (reachability substrate), the attacker profiles (capability gates), the
// ATT&CK applicability/mitigation catalog, and live findings (status) into a
// regenerated-each-cycle projection.
type Service struct {
	repo     tmdom.Repository
	chains   ExposureChainProvider
	assets   asset.Repository
	rels     asset.RelationshipRepository
	profiles tmdom.AttackerProfileReader
	findings tmdom.FindingReader
	logger   *logger.Logger
}

// NewService wires the generation service.
func NewService(
	repo tmdom.Repository,
	chains ExposureChainProvider,
	assets asset.Repository,
	rels asset.RelationshipRepository,
	profiles tmdom.AttackerProfileReader,
	findings tmdom.FindingReader,
	log *logger.Logger,
) *Service {
	return &Service{
		repo:     repo,
		chains:   chains,
		assets:   assets,
		rels:     rels,
		profiles: profiles,
		findings: findings,
		logger:   log.With("service", "threat_model"),
	}
}

// List returns threat models for the tenant, filtered and paginated.
func (s *Service) List(ctx context.Context, tenantID shared.ID, filter tmdom.ModelFilter, page pagination.Pagination) ([]*tmdom.ThreatModel, int, error) {
	return s.repo.ListModels(ctx, tenantID, filter, page)
}

// Get returns a model and its (optionally filtered) threats, tenant-scoped.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID, filter tmdom.ThreatFilter) (*tmdom.ThreatModel, []*tmdom.ThreatModelThreat, error) {
	model, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	threats, err := s.repo.ListThreats(ctx, tenantID, id, filter)
	if err != nil {
		return nil, nil, err
	}
	if len(threats) > 0 {
		version := model.TechniqueDatasetVersion
		if version == "" {
			version = tmdom.DefaultDatasetVersion
		}
		mits, merr := s.repo.ListTechniqueMitigations(ctx, version)
		if merr != nil {
			return nil, nil, fmt.Errorf("load mitigation catalog: %w", merr)
		}
		enrichThreatCatalog(mits, threats)
	}
	return model, threats, nil
}

// enrichThreatCatalog fills the read-time catalog fields (technique/mitigation
// names + mitigation summary) on threats from the technique→mitigation catalog.
// Pure and allocation-bounded: it builds one lookup map from a single catalog
// slice (one query per request — no N+1) and never mutates persisted state. A
// threat whose (technique_id, mitigation_id) has no catalog row keeps empty
// names so callers fall back to the raw ids.
func enrichThreatCatalog(mits []tmdom.TechniqueMitigation, threats []*tmdom.ThreatModelThreat) {
	if len(threats) == 0 || len(mits) == 0 {
		return
	}
	byPair := make(map[string]tmdom.TechniqueMitigation, len(mits))
	techName := make(map[string]string, len(mits))
	for _, m := range mits {
		byPair[catalogPairKey(m.TechniqueID, m.MitigationID)] = m
		if _, ok := techName[m.TechniqueID]; !ok {
			techName[m.TechniqueID] = m.TechniqueName
		}
	}
	for _, t := range threats {
		if t == nil {
			continue
		}
		if name, ok := techName[t.TechniqueID]; ok {
			t.TechniqueName = name
		}
		if m, ok := byPair[catalogPairKey(t.TechniqueID, t.MitigationID)]; ok {
			t.MitigationName = m.MitigationName
			t.MitigationSummary = m.MitigationSummary
		}
	}
}

func catalogPairKey(techniqueID, mitigationID string) string {
	return techniqueID + "|" + mitigationID
}

// GenerateForScope (re)generates the threat model for a scope and returns the
// persisted model. It is idempotent: when the graph/findings/profile inputs are
// unchanged since the last generation (equal input_hash) it returns the existing
// model without rewriting the threats.
func (s *Service) GenerateForScope(ctx context.Context, tenantID shared.ID, scopeType tmdom.ScopeType, scopeRefID *shared.ID) (*tmdom.ThreatModel, error) {
	if !scopeType.Valid() {
		return nil, tmdom.ErrInvalidScope
	}

	name, targetSet, allTargets, err := s.resolveScope(ctx, tenantID, scopeType, scopeRefID)
	if err != nil {
		return nil, err
	}

	chainRes, err := s.chains.GetExposureChains(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load exposure chains: %w", err)
	}
	edges, err := s.rels.ListAllEdges(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load edges: %w", err)
	}
	edgeType, compensating := indexEdges(edges)

	// Resolve the concrete target set for a tenant-wide model now that we have the
	// chains: prefer crown-jewel targets, else every dangerous target.
	if allTargets {
		targetSet = tenantTargets(chainRes.Chains)
	}

	// Keep only chains that reach an in-scope target.
	scoped := make([]attack.ExposureChain, 0, len(chainRes.Chains))
	for i := range chainRes.Chains {
		if targetSet[chainRes.Chains[i].TargetID] {
			scoped = append(scoped, chainRes.Chains[i])
		}
	}

	profs, err := s.loadProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	applic, err := s.repo.ListApplicability(ctx, tmdom.DefaultDatasetVersion)
	if err != nil {
		return nil, fmt.Errorf("load applicability catalog: %w", err)
	}
	mitIdx, err := s.mitigationIndex(ctx)
	if err != nil {
		return nil, err
	}

	// Findings for every hop asset appearing in the scoped chains.
	assetIDs := hopAssetIDs(scoped)
	findings, err := s.findings.ListThreatFindings(ctx, tenantID, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("load findings: %w", err)
	}

	model, err := tmdom.NewThreatModel(tenantID, scopeType, scopeRefID, name)
	if err != nil {
		return nil, err
	}
	model.TechniqueDatasetVersion = tmdom.DefaultDatasetVersion
	model.InputHash = inputHash(scoped, findings, profs, edges)

	// No-op detection: identical inputs since last generation → return as-is.
	if existing, gerr := s.repo.GetByScope(ctx, tenantID, scopeType, scopeRefID); gerr == nil {
		if existing.InputHash != "" && existing.InputHash == model.InputHash {
			s.logger.Debug("threat model inputs unchanged; skipping regeneration",
				"model_id", existing.ID.String(), "scope_type", scopeType.String())
			return existing, nil
		}
	} else if !errors.Is(gerr, tmdom.ErrNotFound) {
		return nil, fmt.Errorf("check existing model: %w", gerr)
	}

	threats := s.enumerate(tenantID, scoped, profs, applic, mitIdx, edgeType, compensating, findings)

	model.RecomputeRollups(threats)
	if err := s.repo.Save(ctx, model, threats); err != nil {
		return nil, fmt.Errorf("save threat model: %w", err)
	}
	s.logger.Info("generated threat model",
		"model_id", model.ID.String(), "scope_type", scopeType.String(),
		"chains", len(scoped), "profiles", len(profs), "threats", len(threats))
	return model, nil
}

// resolveScope validates the scope and returns the model name, the concrete
// in-scope target-asset set, and whether the target set must be derived from the
// chains later (tenant-wide models).
func (s *Service) resolveScope(ctx context.Context, tenantID shared.ID, scopeType tmdom.ScopeType, scopeRefID *shared.ID) (name string, targets map[string]bool, allTargets bool, err error) {
	switch scopeType {
	case tmdom.ScopeCrownJewel, tmdom.ScopeAssetGroup, tmdom.ScopeBusinessUnit:
		if scopeType == tmdom.ScopeCrownJewel {
			if scopeRefID == nil {
				return "", nil, false, fmt.Errorf("%w: scope_ref_id is required for a crown_jewel scope", shared.ErrValidation)
			}
			a, gerr := s.assets.GetByID(ctx, tenantID, *scopeRefID)
			if gerr != nil {
				return "", nil, false, fmt.Errorf("resolve crown-jewel asset: %w", gerr)
			}
			return "Threat model: " + a.Name(), map[string]bool{scopeRefID.String(): true}, false, nil
		}
		// asset_group / business_unit membership resolution is not implemented in
		// this generation step (needs group/BU membership joins). Reject clearly
		// rather than silently modeling the wrong targets.
		return "", nil, false, fmt.Errorf("%w: scope_type %q is not yet supported for generation", shared.ErrValidation, scopeType)
	case tmdom.ScopeTenant:
		return "Tenant threat model", nil, true, nil
	default:
		return "", nil, false, tmdom.ErrInvalidScope
	}
}

// loadProfiles returns the tenant's attacker profiles, or a single synthetic
// external-unauthenticated profile when none are configured so generation still
// produces the baseline internet-facing threats.
func (s *Service) loadProfiles(ctx context.Context, tenantID shared.ID) ([]tmdom.AttackerProfileFact, error) {
	profs, err := s.profiles.ListAttackerProfiles(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load attacker profiles: %w", err)
	}
	if len(profs) == 0 {
		return []tmdom.AttackerProfileFact{{
			Name:        "External Unauthenticated (default)",
			ProfileType: "external_unauth",
			Capabilities: tmdom.AttackerCapabilities{
				NetworkAccess:   tmdom.NetworkExternal,
				CredentialLevel: tmdom.CredentialNone,
			},
		}}, nil
	}
	return profs, nil
}

// mitigationIndex maps each technique id to its representative tactic +
// mitigation id (the first mitigation in catalog order).
func (s *Service) mitigationIndex(ctx context.Context) (map[string]techInfo, error) {
	mits, err := s.repo.ListTechniqueMitigations(ctx, tmdom.DefaultDatasetVersion)
	if err != nil {
		return nil, fmt.Errorf("load mitigation catalog: %w", err)
	}
	idx := make(map[string]techInfo, len(mits))
	for _, m := range mits {
		if _, ok := idx[m.TechniqueID]; ok {
			continue // keep first (deterministic: catalog is ordered)
		}
		idx[m.TechniqueID] = techInfo{tactic: m.Tactic, mitigationID: m.MitigationID}
	}
	return idx, nil
}

type techInfo struct {
	tactic       string
	mitigationID string
}

// enumerate walks every (attacker profile × scoped chain × hop × applicable
// technique) and emits a threat with a live-derived status. Combinatorics are
// bounded per hop (maxTechniquesPerHop) and overall (maxThreats).
func (s *Service) enumerate(
	tenantID shared.ID,
	chains []attack.ExposureChain,
	profs []tmdom.AttackerProfileFact,
	applic []tmdom.TechniqueApplicability,
	mitIdx map[string]techInfo,
	edgeType map[string]string,
	compensating map[string]bool,
	findings []tmdom.FindingFact,
) []*tmdom.ThreatModelThreat {
	byAsset := findingsByAsset(findings)
	threats := make([]*tmdom.ThreatModelThreat, 0, 256)
	seen := make(map[string]bool)
	truncatedHops := 0

	for pi := range profs {
		prof := profs[pi]
		var profileID *shared.ID
		if !prof.ID.IsZero() {
			id := prof.ID
			profileID = &id
		}
		for ci := range chains {
			ch := chains[ci]
			if !chainReachableBy(prof.Capabilities, ch) {
				continue
			}
			fp := chainFingerprint(ch.Hops)
			for hopIndex := range ch.Hops {
				hop := ch.Hops[hopIndex]
				et := ""
				if hopIndex > 0 {
					et = edgeType[edgeKey(ch.Hops[hopIndex-1].AssetID, hop.AssetID)]
				}
				techs := applicableTechniques(hop.AssetType, et, prof.Capabilities, applic)
				if len(techs) > maxTechniquesPerHop {
					sort.SliceStable(techs, func(i, j int) bool { return techs[i].Weight > techs[j].Weight })
					techs = techs[:maxTechniquesPerHop]
					truncatedHops++
				}
				for _, tech := range techs {
					dedupKey := profileKey(profileID) + "|" + fp + "|" + strconv.Itoa(hopIndex) + "|" + tech.TechniqueID
					if seen[dedupKey] {
						continue
					}
					seen[dedupKey] = true

					info := mitIdx[tech.TechniqueID]
					status, reason, evid := deriveStatus(tech.TechniqueID, nil, hop.AssetID, byAsset[hop.AssetID], compensating[hop.AssetID])

					t, err := tmdom.NewThreatModelThreat(tenantID, shared.ID{}, status)
					if err != nil {
						continue
					}
					t.AttackerProfileID = profileID
					t.EntryPointAssetID = parseID(ch.EntryPointID)
					t.TargetAssetID = parseID(ch.TargetID)
					t.HopAssetID = parseID(hop.AssetID)
					t.HopIndex = hopIndex
					t.ChainFingerprint = fp
					t.TechniqueID = tech.TechniqueID
					t.Tactic = info.tactic
					t.MitigationID = info.mitigationID
					t.StatusReason = reason
					t.EvidenceFindingID = evid
					t.Score = ch.Score * tech.Weight
					threats = append(threats, t)
				}
			}
		}
	}

	if truncatedHops > 0 {
		s.logger.Warn("truncated techniques on some hops (per-hop cap)",
			"cap", maxTechniquesPerHop, "hops_truncated", truncatedHops)
	}
	if len(threats) > maxThreats {
		sort.SliceStable(threats, func(i, j int) bool { return threats[i].Score > threats[j].Score })
		s.logger.Warn("truncated threats to overall cap", "cap", maxThreats, "generated", len(threats))
		threats = threats[:maxThreats]
	}
	return threats
}

// chainReachableBy applies the chain-level capability gate: an external-only
// attacker can only start from a public entry point. Exposure chains always
// originate at a public entry, so this passes for them; internal / physical
// attackers can start anywhere and always pass. The check is kept explicit so
// the invariant survives future changes to the chain source.
func chainReachableBy(caps tmdom.AttackerCapabilities, ch attack.ExposureChain) bool {
	if tmdom.NetworkRank(caps.NetworkAccess) > tmdom.NetworkRank(tmdom.NetworkExternal) {
		return true // internal/physical attacker: no entry-point restriction
	}
	if len(ch.Hops) == 0 {
		return false
	}
	return ch.Hops[0].Exposure == string(asset.ExposurePublic)
}

// ---- helpers ---------------------------------------------------------------

func indexEdges(edges []asset.RelationshipEdge) (edgeType map[string]string, compensating map[string]bool) {
	edgeType = make(map[string]string, len(edges))
	compensating = make(map[string]bool)
	for _, e := range edges {
		edgeType[edgeKey(e.SourceAssetID, e.TargetAssetID)] = string(e.Type)
		switch e.Type {
		case asset.RelTypeProtectedBy:
			// "X protected_by Y": the protected asset is the source.
			compensating[e.SourceAssetID] = true
		case asset.RelTypeMonitors:
			// "Y monitors X": the monitored asset is the target.
			compensating[e.TargetAssetID] = true
		}
	}
	return edgeType, compensating
}

func edgeKey(src, tgt string) string { return src + ">" + tgt }

func tenantTargets(chains []attack.ExposureChain) map[string]bool {
	crown := make(map[string]bool)
	all := make(map[string]bool)
	for i := range chains {
		all[chains[i].TargetID] = true
		if chains[i].IsCrownJewel {
			crown[chains[i].TargetID] = true
		}
	}
	if len(crown) > 0 {
		return crown
	}
	return all
}

func hopAssetIDs(chains []attack.ExposureChain) []shared.ID {
	seen := make(map[string]bool)
	ids := make([]shared.ID, 0)
	for i := range chains {
		for _, h := range chains[i].Hops {
			if seen[h.AssetID] {
				continue
			}
			seen[h.AssetID] = true
			if id, err := shared.IDFromString(h.AssetID); err == nil {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func findingsByAsset(findings []tmdom.FindingFact) map[string][]tmdom.FindingFact {
	m := make(map[string][]tmdom.FindingFact)
	for _, f := range findings {
		k := f.AssetID.String()
		m[k] = append(m[k], f)
	}
	return m
}

// chainFingerprint is a stable hash of the ordered hop asset ids (entry→target).
// Two regenerations of the same physical path produce the same fingerprint,
// letting the same chain be tracked across cycles independent of scoring.
func chainFingerprint(hops []attack.ChainHop) string {
	h := sha256.New()
	for i, hop := range hops {
		if i > 0 {
			_, _ = h.Write([]byte(">"))
		}
		_, _ = h.Write([]byte(hop.AssetID))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// inputHash is a stable hash of every generation input (scoped graph, findings,
// profiles, edges + dataset version) so an unchanged regeneration is a no-op.
func inputHash(chains []attack.ExposureChain, findings []tmdom.FindingFact, profs []tmdom.AttackerProfileFact, edges []asset.RelationshipEdge) string {
	parts := make([]string, 0, len(chains)+len(findings)+len(profs)+len(edges)+1)
	parts = append(parts, "v="+tmdom.DefaultDatasetVersion)
	for i := range chains {
		parts = append(parts, "c="+chainFingerprint(chains[i].Hops)+":"+strconv.FormatFloat(chains[i].Score, 'f', 4, 64))
	}
	for _, f := range findings {
		parts = append(parts, "f="+f.AssetID.String()+":"+f.TechniqueID+":"+f.Status+":"+joinSorted(f.CWEIDs))
	}
	for _, p := range profs {
		parts = append(parts, "p="+p.ID.String()+":"+p.Capabilities.NetworkAccess+":"+p.Capabilities.CredentialLevel+":"+strconv.FormatBool(p.Capabilities.Persistence))
	}
	for _, e := range edges {
		parts = append(parts, "e="+e.SourceAssetID+">"+e.TargetAssetID+":"+string(e.Type))
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func joinSorted(ss []string) string {
	c := append([]string(nil), ss...)
	sort.Strings(c)
	out := ""
	for i, s := range c {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func parseID(s string) *shared.ID {
	if s == "" {
		return nil
	}
	id, err := shared.IDFromString(s)
	if err != nil {
		return nil
	}
	return &id
}

func profileKey(id *shared.ID) string {
	if id == nil {
		return "-"
	}
	return id.String()
}
