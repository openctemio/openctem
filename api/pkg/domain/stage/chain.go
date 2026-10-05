package stage

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// Feeds reports whether pred's outputs can be next's inputs: at least one
// type pred produces is a type next accepts. A stage that only reports
// findings feeds nothing.
func Feeds(pred, next Stage) bool {
	for _, out := range pred.Outputs {
		if next.Accepts(asset.CanonicalPair(out, "")) {
			return true
		}
	}
	return false
}

// FromSeeds names the run's seeds in a ChainStage's From.
const FromSeeds = "seeds"

// ChainStage is one stage of an engine as the validator sees it.
type ChainStage struct {
	// ID is the stage's key inside the engine ("subdomains", "ports").
	ID string
	// Stage is the catalog capability it runs.
	Stage Key
	// From lists the engine stage ids (and FromSeeds) it takes targets
	// from. Empty means the seeds and every earlier stage whose outputs it
	// accepts (edges derived from types).
	From []string
}

// ValidateChain checks an engine's stages against the catalog (research/27
// §4.1): every stage is a catalog stage, ids are unique, From names only
// earlier stages or the seeds (so there is no cycle), a stage that does not
// take the seeds takes at least one type its From stages produce (the
// "nothing produces its inputs" trap that otherwise yields silently empty
// stages), and no stage is intrusive (T2 needs an approval flow the engine
// spec does not have yet).
func ValidateChain(stages []ChainStage) error {
	if len(stages) == 0 {
		return fmt.Errorf("an engine needs at least one stage")
	}
	seen := map[string]Stage{}
	for i, cs := range stages {
		id := strings.TrimSpace(cs.ID)
		if id == "" || id == FromSeeds {
			return fmt.Errorf("stage %d: invalid id %q", i+1, cs.ID)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("stage %q: duplicate id", id)
		}
		st, ok := Lookup(cs.Stage)
		if !ok {
			return fmt.Errorf("stage %q: unknown capability %q", id, cs.Stage)
		}
		if st.Tier >= TierIntrusive {
			return fmt.Errorf("stage %q: %s is intrusive (T2) and needs an approval", id, st.Key)
		}
		if err := validateFrom(id, st, cs.From, seen); err != nil {
			return err
		}
		seen[id] = st
	}
	return nil
}

func validateFrom(id string, st Stage, from []string, earlier map[string]Stage) error {
	if len(from) == 0 {
		return nil // seeds plus every compatible earlier stage
	}
	fed := false
	for _, f := range from {
		f = strings.TrimSpace(f)
		if f == FromSeeds {
			fed = true
			continue
		}
		pred, ok := earlier[f]
		if !ok {
			return fmt.Errorf("stage %q: takes targets from %q, which is not an earlier stage", id, f)
		}
		if Feeds(pred, st) {
			fed = true
		}
	}
	if !fed {
		return fmt.Errorf("stage %q: nothing it takes targets from produces %s", id, typeList(st.Inputs))
	}
	return nil
}

func typeList(ts []asset.AssetType) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = string(t)
	}
	return strings.Join(parts, ", ")
}
