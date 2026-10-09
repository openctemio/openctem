package command

import (
	"encoding/json"
	"strings"
)

// PayloadTool is the tool a command payload asks for: "scanner", else
// "preferred_tool" (the keys the zone claim predicate and ingest read), or
// "".
func PayloadTool(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var p struct {
		Scanner       string `json:"scanner"`
		PreferredTool string `json:"preferred_tool"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	if p.Scanner != "" {
		return p.Scanner
	}
	return p.PreferredTool
}

// PayloadTargets are the targets a command payload names ("targets" and
// "target", the keys sensors read), trimmed and de-duplicated, in order.
func PayloadTargets(payload json.RawMessage) []string {
	if len(payload) == 0 {
		return nil
	}
	var p struct {
		Targets []any `json:"targets"`
		Target  any   `json:"target"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v any) {
		s, ok := v.(string)
		if !ok {
			return
		}
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, t := range p.Targets {
		add(t)
	}
	add(p.Target)
	return out
}
