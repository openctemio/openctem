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
