// Package aiprompt holds the prompt-injection defenses every AI prompt the
// platform builds shares: Unicode normalisation, the known-injection filter
// and the nonce fence around untrusted text. Design:
// docs/architecture/ai-triage.md (prompt injection).
package aiprompt

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// Sanitizer sanitizes user-provided data before including in prompts.
type Sanitizer struct {
	maxFieldLength int
}

// NewSanitizer creates a new prompt sanitizer.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		maxFieldLength: 10000, // Max 10KB per field
	}
}

// SanitizeForPrompt sanitizes a string for inclusion in an LLM prompt.
// Applies unicode normalization to prevent bypass via homoglyphs and special characters.
func (s *Sanitizer) SanitizeForPrompt(text string) string {
	if text == "" {
		return ""
	}

	// SECURITY: Normalize unicode to prevent homoglyph attacks
	// Attackers can use characters like "ｉｇｎｏｒｅ" (fullwidth) instead of "ignore"
	// or "іgnore" (Cyrillic 'і') to bypass ASCII-based regex filters
	text = NormalizeUnicode(text)

	// Truncate if too long (after normalization to avoid truncating in middle of char)
	if len(text) > s.maxFieldLength {
		text = text[:s.maxFieldLength] + "\n[TRUNCATED]"
	}

	// Remove potential prompt injection patterns
	// These patterns could trick the LLM into ignoring instructions
	// SECURITY: Expanded pattern list to cover more injection techniques
	injectionPatterns := []string{
		// Direct instruction override
		`(?i)ignore (previous|above|all|prior|system) instructions?`,
		`(?i)disregard (previous|above|all|prior|system) instructions?`,
		`(?i)forget (previous|above|all|prior|system) instructions?`,
		`(?i)override (previous|above|all|prior|system) instructions?`,
		`(?i)bypass (previous|above|all|prior|system) instructions?`,
		`(?i)skip (previous|above|all|prior) instructions?`,
		// New instruction injection
		`(?i)new instructions?:`,
		`(?i)updated instructions?:`,
		`(?i)revised instructions?:`,
		`(?i)actual instructions?:`,
		`(?i)real instructions?:`,
		// System prompt access/override
		`(?i)system prompt:`,
		`(?i)system message:`,
		`(?i)output (the|your) (system|initial) (prompt|instructions?)`,
		`(?i)reveal (the|your) (system|initial) (prompt|instructions?)`,
		`(?i)show (the|your) (system|initial) (prompt|instructions?)`,
		`(?i)print (the|your) (system|initial) (prompt|instructions?)`,
		// Role/persona manipulation
		`(?i)you are now`,
		`(?i)you're now`,
		`(?i)from now on,? you`,
		`(?i)act as if`,
		`(?i)pretend (that|to be|you)`,
		`(?i)roleplay as`,
		`(?i)behave as`,
		`(?i)respond as`,
		`(?i)switch (to|into) (a|the)? ?(\w+)? ?mode`,
		`(?i)enter (\w+)? ?mode`,
		`(?i)enable (\w+)? ?mode`,
		// Special tokens/markers (model-specific)
		`(?i)\[SYSTEM\]`,
		`(?i)\[INST\]`,
		`(?i)\[/INST\]`,
		`(?i)<\|im_start\|>`,
		`(?i)<\|im_end\|>`,
		`(?i)<\|system\|>`,
		`(?i)<\|user\|>`,
		`(?i)<\|assistant\|>`,
		`(?i)<<SYS>>`,
		`(?i)<</SYS>>`,
		`(?i)### (System|Instruction|Human|Assistant):?`,
		// Tool call injection
		`(?i)<\|tool_use\|>`,
		`(?i)<function_call>`,
		`(?i)<tool_call>`,
		// Delimiter escape attempts
		`(?i)"""[\s\S]*"""`,
		`(?i)'''[\s\S]*'''`,
		// Output manipulation
		`(?i)always (respond|answer|output|say|reply)`,
		`(?i)never (respond|answer|output|say|reply)`,
		`(?i)only (respond|answer|output|say|reply)`,
		// Security bypass attempts
		`(?i)jailbreak`,
		`(?i)dan mode`,
		`(?i)developer mode`,
		`(?i)sudo mode`,
		`(?i)admin mode`,
	}

	for _, pattern := range injectionPatterns {
		re := regexp.MustCompile(pattern)
		text = re.ReplaceAllString(text, FilteredMarker)
	}

	return text
}

// FilteredMarker replaces text that matched a known prompt-injection pattern.
const FilteredMarker = "[FILTERED]"

// fenceMarkerReplacement replaces fence-like markup found inside untrusted text.
const fenceMarkerReplacement = "[fence-marker-removed]"

// fenceMarkerRe matches tags that look like a prompt fence: the per-request
// <untrusted-...> family (any nonce, any case, optional whitespace or
// attributes) and the legacy static <user_input> tag. Ordinary code such as
// "a < b" or "<div>" does not match.
var fenceMarkerRe = regexp.MustCompile(`(?i)<\s*/?\s*(?:user[_\s-]*input|untrusted(?:[-_][0-9a-z]*)?)\b[^>]*>`)

// Fence delimits untrusted content in a prompt with a tag whose name
// carries a random nonce, so the content cannot contain the closing tag.
type Fence struct {
	tag string
}

// NewFence returns a fence with a fresh 128-bit nonce.
func NewFence() Fence {
	nonce := make([]byte, 16)
	// crypto/rand.Read never returns an error on supported platforms (Go 1.24+).
	_, _ = rand.Read(nonce)
	return Fence{tag: "untrusted-" + hex.EncodeToString(nonce)}
}

// Wrap neutralizes fence-like markup in v and wraps it in the fence. The bool
// reports whether any fence marker had to be removed (an injection attempt).
func (p Fence) Wrap(v string) (string, bool) {
	clean := fenceMarkerRe.ReplaceAllString(v, fenceMarkerReplacement)
	// Belt and braces: the nonce is unguessable, but never let the exact tag
	// through even if the regex were bypassed.
	clean = strings.ReplaceAll(clean, p.tag, fenceMarkerReplacement)
	hit := clean != v
	return "<" + p.tag + ">" + clean + "</" + p.tag + ">", hit
}

// SanitizeCodeSnippet sanitizes a code snippet for inclusion in prompts.
func (s *Sanitizer) SanitizeCodeSnippet(code string) string {
	// Limit code size
	maxCodeLength := 5000
	if len(code) > maxCodeLength {
		code = code[:maxCodeLength] + "\n// [TRUNCATED]"
	}

	return code
}

// NormalizeUnicode normalizes unicode text to prevent homoglyph attacks.
// This converts characters to their closest ASCII equivalents where possible,
// and removes non-printable control characters.
//
// Examples of attacks this prevents:
// - Fullwidth characters: "ｉｇｎｏｒｅ" → "ignore"
// - Cyrillic lookalikes: "іgnore" (Cyrillic і) → "ignore"
// - Mathematical symbols: "𝓲𝓷𝓼𝓽𝓻𝓾𝓬𝓽𝓲𝓸𝓷" → "instruction"
// - Control characters: Zero-width spaces, direction overrides
func NormalizeUnicode(text string) string {
	// Step 1: Apply NFKC normalization
	// This decomposes characters and then recomposes them in a canonical way.
	// It converts fullwidth, halfwidth, and compatibility characters to their
	// standard equivalents. E.g., "ｉｇｎｏｒｅ" → "ignore"
	nfkcTransformer := transform.Chain(
		norm.NFKC,
		// Step 2: Remove non-printable and control characters
		runes.Remove(runes.Predicate(func(r rune) bool {
			// Remove invisible/control characters that could be used to hide text
			// Keep basic ASCII printables, newlines, tabs
			if r == '\n' || r == '\r' || r == '\t' {
				return false // Keep these
			}
			// Remove control characters (except the ones above)
			if unicode.IsControl(r) {
				return true
			}
			// Remove zero-width characters
			if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
				return true
			}
			// Remove directional overrides (can hide text direction)
			if r >= '\u202A' && r <= '\u202E' {
				return true
			}
			// Remove homoglyphs that look like basic ASCII but aren't
			// These are commonly used in prompt injection
			return false
		})),
	)

	result, _, err := transform.String(nfkcTransformer, text)
	if err != nil {
		// If transformation fails, return original text (fail-safe)
		return text
	}

	// Step 3: Additional homoglyph normalization for Cyrillic lookalikes
	// NFKC doesn't catch all cases, especially Cyrillic characters that
	// look identical to Latin characters
	homoglyphReplacements := map[rune]rune{
		'а': 'a', // Cyrillic
		'е': 'e', // Cyrillic
		'і': 'i', // Cyrillic
		'о': 'o', // Cyrillic
		'р': 'p', // Cyrillic
		'с': 'c', // Cyrillic
		'у': 'y', // Cyrillic
		'х': 'x', // Cyrillic
		'А': 'A', // Cyrillic
		'В': 'B', // Cyrillic
		'Е': 'E', // Cyrillic
		'К': 'K', // Cyrillic
		'М': 'M', // Cyrillic
		'Н': 'H', // Cyrillic
		'О': 'O', // Cyrillic
		'Р': 'P', // Cyrillic
		'С': 'C', // Cyrillic
		'Т': 'T', // Cyrillic
		'У': 'Y', // Cyrillic
		'Х': 'X', // Cyrillic
	}

	var sb strings.Builder
	sb.Grow(len(result))
	for _, r := range result {
		if replacement, ok := homoglyphReplacements[r]; ok {
			sb.WriteRune(replacement)
		} else {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

// Tag is the fence's tag name ("untrusted-<nonce>"), for the note that tells
// the model what fenced blocks are.
func (p Fence) Tag() string { return p.tag }
