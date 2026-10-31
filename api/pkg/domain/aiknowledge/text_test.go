package aiknowledge

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTerms(t *testing.T) {
	got := Terms(`  "staging" -waf OR CVE-2024-3094 *.stg.example.com a  Máy_chủ staging  `)
	want := []string{"staging", "waf", "cve-2024-3094", "stg.example.com", "máy_chủ"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("terms = %q, want %q", got, want)
	}
	many := strings.Repeat("word ", 5) + strings.Join([]string{"a1", "b2", "c3", "d4", "e5", "f6", "g7", "h8", "i9", "j10", "k11", "l12", "m13", "n14", "o15", "p16", "q17"}, " ")
	if n := len(Terms(many)); n != MaxTerms {
		t.Fatalf("terms capped at %d, got %d", MaxTerms, n)
	}
	if long := Terms(strings.Repeat("x", 200)); utf8.RuneCountInString(long[0]) != maxTermRunes {
		t.Fatalf("long term not capped: %d", utf8.RuneCountInString(long[0]))
	}
	if len(Terms(`" - or ( ) & | ! : *`)) != 0 {
		t.Fatal("operators only must give no terms")
	}
}

func TestNormalize(t *testing.T) {
	in := "a\r\nb\u200bc\u202e\x00d\n\n\n\n\te\ufeff"
	if got := Normalize(in); got != "a\nbcd\n\n\te" {
		t.Fatalf("normalize = %q", got)
	}
	if Normalize("\xff\xfeok") != "ok" {
		t.Fatal("invalid UTF-8 kept")
	}
}

func TestSplit_HeadingsParagraphsAndLimits(t *testing.T) {
	text := "Intro line.\n\n# Hosts\n\nStaging hosts are *.stg.example.com.\n\n## WAF\nAll public apps sit behind the WAF.\n\n# Patching\n\nPatch on Tuesdays."
	chunks, ok := Split(text)
	if !ok {
		t.Fatal("split refused a small text")
	}
	want := []Chunk{
		{0, "", "Intro line."},
		{1, "Hosts", "Staging hosts are *.stg.example.com."},
		{2, "Hosts > WAF", "All public apps sit behind the WAF."},
		{3, "Patching", "Patch on Tuesdays."},
	}
	if !reflect.DeepEqual(chunks, want) {
		t.Fatalf("chunks = %#v", chunks)
	}

	// Paragraphs fill a chunk up to the target; a huge paragraph is cut.
	para := strings.Repeat("word ", 300) // 1500 runes
	chunks, _ = Split(para + "\n\n" + "short")
	for _, c := range chunks {
		if utf8.RuneCountInString(c.Body) > maxChunkRunes {
			t.Fatalf("chunk over cap: %d", utf8.RuneCountInString(c.Body))
		}
	}
	if len(chunks) < 2 {
		t.Fatalf("long paragraph not cut: %d chunks", len(chunks))
	}

	// Too many chunks: refused.
	var b strings.Builder
	for i := 0; i < MaxChunks+5; i++ {
		b.WriteString("# h\n\nx\n\n")
	}
	if _, ok := Split(b.String()); ok {
		t.Fatal("over MaxChunks accepted")
	}
}
