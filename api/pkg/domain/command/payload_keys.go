package command

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// PayloadKeyDiscoveryMaxRequests is the scanner config key of a path
// discovery job's per-origin request budget (the webguess mapping of the
// contract's max_requests_per_origin).
const PayloadKeyDiscoveryMaxRequests = "max_requests"

// MaxDiscoveryRequests bounds what a payload may ask for as a path discovery
// request budget; the platform's per-origin budget bounds it further when the
// job is dispatched (the web job guard).
const MaxDiscoveryRequests = 100_000

// PayloadScanRunID is the scan run a command payload belongs to (the
// "scan_run_id" key a workflow step carries, else the "run_id" of a single
// scan), or "" when it names none.
func PayloadScanRunID(payload json.RawMessage) string {
	var p struct {
		ScanRunID string `json:"scan_run_id"`
		RunID     string `json:"run_id"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	if id := strings.TrimSpace(p.ScanRunID); id != "" {
		return id
	}
	return strings.TrimSpace(p.RunID)
}

// PayloadDiscoveryMaxRequests is a path discovery job's per-origin request
// budget from its "config" or "scanner_config" (0 when it names none; at
// most MaxDiscoveryRequests).
func PayloadDiscoveryMaxRequests(payload json.RawMessage) int {
	var p struct {
		Config        map[string]any `json:"config"`
		ScannerConfig map[string]any `json:"scanner_config"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return 0
	}
	for _, cfg := range []map[string]any{p.ScannerConfig, p.Config} {
		switch v := cfg[PayloadKeyDiscoveryMaxRequests].(type) {
		case float64:
			if v > 0 {
				return int(min(v, MaxDiscoveryRequests))
			}
		case int:
			if v > 0 {
				return min(v, MaxDiscoveryRequests)
			}
		}
	}
	return 0
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

// ErrTemplateContent: a custom template of a payload does not decode.
var ErrTemplateContent = errors.New("a custom template content is not valid base64")

// PayloadTemplateDigests are the digests of the custom templates a command
// payload carries ("custom_templates"[].content, base64-decoded after
// trimming, as sensors decode it): "sha256:" + lower-case hex, in payload
// order, duplicates kept. nil when it carries none. The job statement
// lists them (jobsign.Statement.Templates).
func PayloadTemplateDigests(payload json.RawMessage) ([]string, error) {
	if len(payload) == 0 || !bytes.Contains(payload, []byte(`"custom_templates"`)) {
		return nil, nil
	}
	var p struct {
		CustomTemplates []struct {
			Content string `json:"content"`
		} `json:"custom_templates"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplateContent, err)
	}
	if len(p.CustomTemplates) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(p.CustomTemplates))
	for i, t := range p.CustomTemplates {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(t.Content))
		if err != nil {
			return nil, fmt.Errorf("%w (template %d)", ErrTemplateContent, i)
		}
		sum := sha256.Sum256(raw)
		out = append(out, "sha256:"+hex.EncodeToString(sum[:]))
	}
	return out, nil
}

// PayloadPortSettings are a scan command's port settings: "ports" (a list,
// "full" or "top-N") and "top_ports" (100, 1000), from its "config" or
// "scanner_config"; "" when absent. Ingest reads them as the coverage of a
// port scan.
func PayloadPortSettings(payload json.RawMessage) (ports, topPorts string) {
	if len(payload) == 0 {
		return "", ""
	}
	var p struct {
		Config        map[string]any `json:"config"`
		ScannerConfig map[string]any `json:"scanner_config"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return "", ""
	}
	str := func(v any) string {
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(x)
		case float64:
			return fmt.Sprintf("%d", int64(x))
		}
		return ""
	}
	for _, cfg := range []map[string]any{p.Config, p.ScannerConfig} {
		if ports == "" {
			ports = str(cfg["ports"])
		}
		if topPorts == "" {
			topPorts = str(cfg["top_ports"])
		}
	}
	return ports, topPorts
}
