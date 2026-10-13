package scanrun

import (
	"encoding/json"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/politeness"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// chunkHostKeys is the hosts a chunk of an active stage sends traffic to
// (github.com/openctemio/sdk-go/pkg/politeness, the function the sensor
// admits the chunk with): a name or the host of a URL or a service; an
// address and the marker of its /24 (IPv6 /120) bucket; for a range, the
// range key of every bucket it covers. Sorted, without duplicates, at most
// politeness.MaxKeys. A passive (T0) stage touches no target host and gets
// none, so it is never held back.
func chunkHostKeys(st stage.Stage, hasStage bool, targets []string) []string {
	if !hasStage || st.Tier.Passive() {
		return nil
	}
	return politeness.Keys(targets, "")
}

// chunkTargets is the targets a chunk's command carries: the chunk's own,
// else the run's target list (a step the target gate did not filter).
func chunkTargets(chunk *scanapp.StepTargets, runContext map[string]any) []string {
	if chunk != nil && chunk.Targets != nil {
		return chunk.Targets
	}
	switch ts := runContext["targets"].(type) {
	case []string:
		return ts
	case []any:
		out := make([]string, 0, len(ts))
		for _, v := range ts {
			if str, ok := v.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// withHostKeys writes the keys the platform holds for a chunk into its
// payload ("host_keys"), so the sensor admits the chunk under exactly these
// keys and never hands back what the platform has just offered. A passive
// stage's chunk carries an empty list: it touches no target host and is
// never held back, on either side.
func withHostKeys(payload json.RawMessage, keys []string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == "null" {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("step command payload: %w", err)
	}
	if keys == nil {
		keys = []string{}
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	fields["host_keys"] = b
	return json.Marshal(fields)
}
