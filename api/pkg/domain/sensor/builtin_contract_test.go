package sensor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"
)

// releasedContract is the contract a released sensor reports for a built-in
// tool (stagetest.Builtins), nil for any other tool.
func releasedContract(tool string) *ToolContract {
	tool = strings.ToLower(strings.TrimSpace(CanonicalTool(tool)))
	for _, f := range stagetest.Builtins() {
		if f.Name != tool {
			continue
		}
		tier := 0
		refs := make([]string, 0, len(f.Implements))
		for _, k := range f.Implements {
			ref := fmt.Sprintf("%s@1", k)
			if cp, ok := capability.Lookup(ref); ok {
				tier = max(tier, cp.TierFloor)
				refs = append(refs, ref)
			}
		}
		return builtinContract(fmt.Sprintf("T%d", tier), refs...)
	}
	return nil
}

// admitReleased is Admit with the contract a released sensor reports for
// the job's tool.
func (g Grant) admitReleased(cmdType string, payload json.RawMessage, zoneID *shared.ID) *GrantRefusal {
	return g.AdmitContract(cmdType, payload, zoneID, releasedContract(JobOf(cmdType, payload).Tool))
}
