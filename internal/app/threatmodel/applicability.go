// Package threatmodel implements the continuous threat-modeling generation
// engine: it resolves a scope's crown-jewel / critical targets, walks the
// exposure-chain graph per attacker profile, and enumerates the applicable
// ATT&CK techniques per hop with a live-derived status (open / mitigated /
// covered / accepted / theoretical). The applicability and status logic are
// pure and IO-free (this file + status.go); service.go orchestrates the IO.
//
// See docs/rfcs/RFC-continuous-threat-modeling.md.
package threatmodel

import (
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

// maxTechniquesPerHop bounds the techniques emitted for a single (attacker, hop)
// pair so a permissive catalog cannot explode the threat count. Highest-weighted
// techniques are kept; truncation is logged by the caller.
const maxTechniquesPerHop = 25

// ApplicableTechnique is one technique that applies at a hop for an attacker,
// carrying the catalog row it matched and the risk weight for scoring.
type ApplicableTechnique struct {
	TechniqueID string
	// EdgeType is the applicability row's edge constraint ("" = any incoming edge).
	EdgeType string
	// Weight in (0,1] scales the chain score for this technique: easy,
	// no-credential techniques weigh full; privilege/persistence-gated ones less.
	Weight float64
}

// capabilityClears reports whether an attacker with caps meets the minimum
// network / credential / persistence requirement of an applicability row.
func capabilityClears(caps tmdom.AttackerCapabilities, row tmdom.TechniqueApplicability) bool {
	if row.MinNetwork != "" && tmdom.NetworkRank(caps.NetworkAccess) < tmdom.NetworkRank(row.MinNetwork) {
		return false
	}
	if row.MinCredential != "" && tmdom.CredentialRank(caps.CredentialLevel) < tmdom.CredentialRank(row.MinCredential) {
		return false
	}
	if row.RequiresPersistence && !caps.Persistence {
		return false
	}
	return true
}

// techniqueWeight derives a deterministic risk weight in (0,1] for a technique
// from how much attacker capability it demands. Techniques reachable with the
// least capability (external, no creds, no persistence) are the most likely to
// be exercised and weigh highest; each additional prerequisite discounts it.
func techniqueWeight(row tmdom.TechniqueApplicability) float64 {
	w := 1.0
	if tmdom.NetworkRank(row.MinNetwork) >= tmdom.NetworkRank(tmdom.NetworkInternal) {
		w -= 0.2
	}
	switch tmdom.CredentialRank(row.MinCredential) {
	case 1: // user
		w -= 0.2
	case 2: // admin
		w -= 0.35
	}
	if row.RequiresPersistence {
		w -= 0.2
	}
	if w < 0.1 {
		w = 0.1
	}
	return w
}

// applicableTechniques filters the applicability catalog to the techniques that
// apply at a hop of the given asset type reached over edgeType, for an attacker
// with caps. A catalog row matches when:
//   - its asset_type equals the hop asset type (exact), and
//   - its edge_type is empty (any incoming edge) or equals edgeType, and
//   - the attacker's capabilities clear its min_network / min_credential /
//     requires_persistence gate.
//
// edgeType is the relationship type of the edge entering the hop; it is "" for
// the chain's entry point (no incoming edge), which only matches any-edge rows.
// The result is deterministic (catalog order preserved) and de-duplicated per
// technique id, keeping the highest weight when a technique has several rows.
func applicableTechniques(
	assetType, edgeType string,
	caps tmdom.AttackerCapabilities,
	catalog []tmdom.TechniqueApplicability,
) []ApplicableTechnique {
	seen := make(map[string]int) // technique id -> index in out
	out := make([]ApplicableTechnique, 0, 8)
	for _, row := range catalog {
		if row.AssetType != assetType {
			continue
		}
		if row.EdgeType != "" && row.EdgeType != edgeType {
			continue
		}
		if !capabilityClears(caps, row) {
			continue
		}
		w := techniqueWeight(row)
		if idx, ok := seen[row.TechniqueID]; ok {
			if w > out[idx].Weight {
				out[idx].Weight = w
				out[idx].EdgeType = row.EdgeType
			}
			continue
		}
		seen[row.TechniqueID] = len(out)
		out = append(out, ApplicableTechnique{
			TechniqueID: row.TechniqueID,
			EdgeType:    row.EdgeType,
			Weight:      w,
		})
	}
	return out
}
