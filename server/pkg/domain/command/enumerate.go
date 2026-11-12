package command

import (
	"encoding/json"
	"strings"
)

// enumerationTools are the tools whose every job enumerates: they request
// names or paths from a candidate list.
var enumerationTools = map[string]bool{"dnsx-enum": true, DiscoveryTool: true}

// PayloadEnumerates reports whether a scan payload enumerates (guesses
// names or paths): its capability, or one of its required capability words,
// is an enumerate.* capability, its tool only enumerates, or its config asks
// for a brute force. A bug bounty program that forbids brute force or
// automated scanning refuses such a job on its targets.
func PayloadEnumerates(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var p struct {
		Capability           string         `json:"capability"`
		RequiredCapabilities []any          `json:"required_capabilities"`
		Config               map[string]any `json:"config"`
		ScannerConfig        map[string]any `json:"scanner_config"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return false
	}
	enumerate := func(w string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(w)), "enumerate.")
	}
	if enumerate(p.Capability) {
		return true
	}
	for _, c := range p.RequiredCapabilities {
		if w, ok := c.(string); ok && enumerate(w) {
			return true
		}
	}
	if enumerationTools[strings.ToLower(strings.TrimSpace(PayloadTool(payload)))] {
		return true
	}
	for _, cfg := range []map[string]any{p.Config, p.ScannerConfig} {
		if m, _ := cfg["method"].(string); strings.EqualFold(strings.TrimSpace(m), "bruteforce") {
			return true
		}
	}
	return false
}
