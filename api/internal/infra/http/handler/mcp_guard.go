package handler

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// The result guard. Everything an MCP tool or prompt returns is read by an
// AI model that may also hold tools able to send data out, and much of it is
// text an attacker can influence (scanner titles, banners, imported reports).
// The guard runs at the one choke point every result passes (untrustedResult,
// dataMessage and the final tool-result step), so a new tool cannot forget it:
//
//   - hidden text is removed (bidi controls, zero-width characters, Unicode tag
//     characters, C0/C1 controls), so the model reads what a person would see;
//   - secrets are redacted (keys, tokens, private key blocks, password=...);
//   - every string is capped by field kind, and a cut field ends with "…";
//   - the whole result is capped, so a large tenant cannot flood the context.

// Caps by field kind. Titles and names are one line; narrative fields (the
// pentest write-up) are long; everything else is short.
const (
	mcpMaxTitleRunes = safetext.MaxTitleRunes       // 240
	mcpMaxLongRunes  = safetext.MaxDescriptionRunes // 16000
	mcpMaxShortRunes = safetext.MaxInlineRunes      // 1024

	// mcpMaxResultBytes caps one serialized result or prompt data message.
	mcpMaxResultBytes = 256 * 1024
)

// mcpResultTooLargeMessage is the typed error for a result over the cap.
const mcpResultTooLargeMessage = "the result is too large to return; ask for fewer items (a smaller limit or a narrower filter)"

// mcpLongFields are the narrative fields allowed the long cap.
var mcpLongFields = map[string]bool{
	"description": true, "steps_to_reproduce": true, "business_impact": true,
	"technical_impact": true, "remediation_guidance": true, "notes": true,
	"reason": true, "content": true, "body": true, "template": true,
}

// mcpTitleFields are one-line names and titles.
var mcpTitleFields = map[string]bool{
	"title": true, "name": true, "finding_title": true, "rule_name": true,
}

func mcpFieldCap(key string) int {
	switch {
	case mcpTitleFields[key]:
		return mcpMaxTitleRunes
	case mcpLongFields[key]:
		return mcpMaxLongRunes
	}
	return mcpMaxShortRunes
}

// guardString cleans, redacts and caps one string.
func guardString(s string, limit int) string {
	return safetext.Truncate(safetext.RedactSecrets(safetext.Clean(s)), limit)
}

// guardUntrusted returns v with every string cleaned, redacted and capped.
// The payload is round-tripped through JSON so any Go type (structs, typed
// slices) is walked the way the client will see it. A value that cannot be
// marshaled is returned unchanged: the caller's own marshal then fails the
// call, nothing unguarded is ever sent.
func guardUntrusted(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return v
	}
	return guardWalk(generic, "")
}

func guardWalk(v any, key string) any {
	switch t := v.(type) {
	case string:
		return guardString(t, mcpFieldCap(key))
	case []any:
		for i := range t {
			t[i] = guardWalk(t[i], key)
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			ck := safetext.SingleLine(k, mcpMaxTitleRunes)
			out[ck] = guardWalk(val, strings.ToLower(ck))
		}
		return out
	}
	return v
}
