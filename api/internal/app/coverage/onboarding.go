package coverage

// Deep onboarding of new roots (docs/architecture/asset-coverage.md, "Deep
// onboarding"; research decision D9): the first subdomain enumeration of a
// root domain runs once at deep depth (the medium wordlist pack, with the
// learned labels and their permutations), then the root returns to the
// weekly standard pass (the small pack).
//
// A root is new while its enumerate.subdomains pair in the ledger has never
// succeeded (no last success). The ledger is the record of "once": the pair
// settles covered when the deep run finishes, so a restart, a second API
// replica or a later pass never repeats it, and no extra table is needed. A
// deep pass that keeps failing falls back to standard after
// OnboardingDeepAttempts failures in a row, so a root is never left without
// enumeration.
//
// Threat model. Onboarding changes only the size of the label list; which
// roots may be enumerated is decided exactly as for the steady pass: the
// pair exists only for a root under an active scope entry (the rule's
// requires: [scope_entry]), and StartCoverage runs the full dispatch gate
// (scope entries, exclusions, tier, zone, shared-sensor domain proof) and
// the claim-time re-check. A refused root is blocked and never reaches a
// sensor at any depth. The state read here is one tenant's ledger rows
// (DueBatch is tenant-scoped), so one tenant's onboarding never changes
// another's. The load on third-party name servers is bounded by one deep
// run per tenant at a time, at most MaxOnboardingBatch roots per run, the
// sensor's rate limit and line cap, and the attempt bound.

import (
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

const (
	// OnboardingDeepAttempts is how many failed deep passes in a row a root
	// gets before its enumeration falls back to standard depth.
	OnboardingDeepAttempts = 3
	// MaxOnboardingBatch caps the roots of one deep run: the medium pack
	// allows ten times the lines of the small one, so a tenant adding many
	// roots at once has them onboarded a few at a time (one coverage run of
	// a capability is active at a time).
	MaxOnboardingBatch = 10
)

// onboards reports whether a due pair of the capability is a root still to
// be onboarded with a deep pass: subdomain enumeration of a root domain
// whose pair never succeeded and has not used up its deep attempts.
func onboards(capability string, d covdom.DueTarget) bool {
	return capability == string(stage.EnumerateSubdomains) &&
		d.Type == asset.AssetTypeDomain &&
		d.NeverCovered &&
		d.FailStreak+d.PlatformFailStreak < OnboardingDeepAttempts
}

// onboardingBatch picks the run to start from a due batch: the roots still
// to be onboarded (at most MaxOnboardingBatch) at deep depth when there is
// any, else the whole batch at standard depth. The pairs left out stay due
// and go in a later pass, once the deep run has finished (new roots first).
func onboardingBatch(capability string, due []covdom.DueTarget) ([]covdom.DueTarget, scanworkflow.Depth) {
	deep := make([]covdom.DueTarget, 0, min(len(due), MaxOnboardingBatch))
	for _, d := range due {
		if len(deep) == MaxOnboardingBatch {
			break
		}
		if onboards(capability, d) {
			deep = append(deep, d)
		}
	}
	if len(deep) == 0 {
		return due, scanworkflow.DepthStandard
	}
	return deep, scanworkflow.DepthDeep
}
