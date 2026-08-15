package finding

import "github.com/openctemio/api/pkg/domain/asset"

// ciaImpact maps an asset's CIA business-impact rating (Scoping-stage
// critical-asset register: impact_confidentiality/integrity/availability) into
// the priority engine's business-impact signal.
//
// It returns:
//   - score:  the MAX across the three legs mapped high->5, moderate->3, low->1,
//     unset->0. Folded into the priority impact sub-score as an ONLY-RAISE MAX.
//   - high:   true when at least one leg is rated "high" (severe/catastrophic);
//     lets the classifier bump a borderline finding one band.
//   - detail: the highest-rated leg + rating for the audit reason, e.g.
//     "confidentiality=high". Empty when no rating is set.
//
// The ctem.org Prioritization model lists CIA impact as a Business-Impact input;
// findings carry no CVSS CIA vector, so the rating comes from the asset. A nil
// asset or no ratings set (every existing asset) yields (0, false, "") — zero
// behavior change.
func ciaImpact(a *asset.Asset) (score float64, high bool, detail string) {
	if a == nil {
		return 0, false, ""
	}
	// Ordered so ties prefer confidentiality, then integrity, then availability
	// for the detail string (purely cosmetic — the score is the MAX either way).
	legs := []struct {
		name   string
		rating asset.ImpactRating
	}{
		{"confidentiality", a.ImpactConfidentiality()},
		{"integrity", a.ImpactIntegrity()},
		{"availability", a.ImpactAvailability()},
	}
	best := -1.0
	for _, leg := range legs {
		s := ciaLegScore(leg.rating)
		if s > best {
			best = s
			detail = leg.name + "=" + leg.rating.String()
		}
		if leg.rating == asset.ImpactRatingHigh {
			high = true
		}
	}
	if best <= 0 {
		// No leg rated (all unset) — no CIA signal, no detail.
		return 0, false, ""
	}
	return best, high, detail
}

// ciaLegScore maps one CIA leg's rating to its 0–5 impact contribution.
func ciaLegScore(r asset.ImpactRating) float64 {
	switch r {
	case asset.ImpactRatingHigh:
		return 5
	case asset.ImpactRatingModerate:
		return 3
	case asset.ImpactRatingLow:
		return 1
	default:
		return 0
	}
}
