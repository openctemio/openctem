package safetext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// trojan is a title a hostile target can serve: an RLO override that makes
// "exe.txt" display as "txt.exe", a zero-width space, an LRI isolate, a NUL,
// an escape sequence and a BOM.
const trojan = "invoice\u202Etxt.exe\u200B \u2066admin\u2069\x00\x1b[31m\uFEFFend"

func TestClean_RemovesBidiControlAndInvisible(t *testing.T) {
	got := Clean(trojan)
	for _, bad := range []string{"\u202E", "\u200B", "\u2066", "\u2069", "\x00", "\x1b", "\uFEFF"} {
		if strings.Contains(got, bad) {
			t.Fatalf("Clean left %q in %q", bad, got)
		}
	}
	if got != "invoicetxt.exe admin[31mend" {
		t.Fatalf("Clean = %q", got)
	}
}

func TestClean_KeepsTextNewlineTabAndJoiners(t *testing.T) {
	in := "line1\r\nline2\rline3\tTab ok ü 日本 👩\u200D💻 \u200C"
	want := "line1\nline2\nline3\tTab ok ü 日本 👩\u200D💻 \u200C"
	if got := Clean(in); got != want {
		t.Fatalf("Clean = %q, want %q", got, want)
	}
}

func TestClean_InvalidUTF8(t *testing.T) {
	got := Clean("a\xffb")
	if !utf8.ValidString(got) || got != "a�b" {
		t.Fatalf("Clean = %q", got)
	}
}

func TestTruncateAndSingleLine(t *testing.T) {
	if got := Truncate("abcdef", 4); got != "abc…" {
		t.Fatalf("Truncate = %q", got)
	}
	if got := Truncate("日本語", 3); got != "日本語" {
		t.Fatalf("Truncate counts runes, got %q", got)
	}
	if got := SingleLine("  a\n\n b\t c  ", 100); got != "a b c" {
		t.Fatalf("SingleLine = %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := SingleLine(long, MaxTitleRunes); utf8.RuneCountInString(got) != MaxTitleRunes {
		t.Fatalf("SingleLine cap: %d runes", utf8.RuneCountInString(got))
	}
}

func TestDefang(t *testing.T) {
	got := Defang("see https://evil.test/a and HTTP://x.test, ftp://f, javascript:alert(1), mailto:a@b.test")
	for _, bad := range []string{"https://", "HTTP://", "ftp://", "mailto:a"} {
		if strings.Contains(got, bad) {
			t.Fatalf("Defang left %q in %q", bad, got)
		}
	}
	if !strings.Contains(got, "https[:]//evil.test/a") {
		t.Fatalf("Defang should keep the URL readable: %q", got)
	}
}

// jiraPayloads inject a link, a mention, an image (tracking pixel), a macro,
// a table and a heading into Jira wiki markup.
var jiraPayloads = []string{
	"[Click to re-authenticate|https://evil.test/login]",
	"[~admin] please approve",
	"!https://evil.test/pixel.png!",
	"{html}<script>alert(1)</script>{html}",
	"{panel:title=Urgent}Pay here{panel}",
	"|| a || b ||\n| c | d |",
	"h1. Fake heading",
	"*bold* _it_ -strike- +under+ ^sup^ ~sub~ ??cite??",
	"\\\\[link|https://evil.test]",
}

func TestJiraWikiInline_EscapesEveryMarkupCharacter(t *testing.T) {
	for _, p := range jiraPayloads {
		got := JiraWikiInline(p, MaxInlineRunes)
		// Every markup character must be preceded by a backslash: strip the
		// escaped pairs and check none is left bare.
		bare := strings.NewReplacer(
			`\\`, "", `\{`, "", `\}`, "", `\[`, "", `\]`, "", `\|`, "", `\!`, "",
			`\*`, "", `\_`, "", `\^`, "", `\~`, "", `\+`, "", `\-`, "", `\?`, "", `\#`, "",
		).Replace(got)
		if strings.ContainsAny(bare, `{}[]|!*_^~+-?#\`) {
			t.Errorf("JiraWikiInline(%q) = %q leaves bare markup %q", p, got, bare)
		}
		if strings.Contains(got, "https://") {
			t.Errorf("JiraWikiInline(%q) = %q leaves a clickable URL", p, got)
		}
		if strings.Contains(got, "\n") {
			t.Errorf("JiraWikiInline(%q) = %q is not one line", p, got)
		}
	}
}

func TestJiraWikiBlock_CannotBeClosedEarly(t *testing.T) {
	in := "before{noformat}\n[evil|https://evil.test]\n{NoFormat}{html}x{html}\u202Eafter"
	got := JiraWikiBlock(in, MaxDescriptionRunes)
	if !strings.HasPrefix(got, "{noformat}\n") || !strings.HasSuffix(got, "\n{noformat}") {
		t.Fatalf("not wrapped: %q", got)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "{noformat}\n"), "\n{noformat}")
	if strings.Contains(strings.ToLower(inner), "{noformat") {
		t.Fatalf("inner text can close the block: %q", inner)
	}
	if strings.Contains(inner, "https://") || strings.Contains(inner, "\u202E") {
		t.Fatalf("inner text not neutralized: %q", inner)
	}
}

func TestJiraWikiBlock_Caps(t *testing.T) {
	got := JiraWikiBlock(strings.Repeat("a", 50), 10)
	if got != "{noformat}\naaaaaaaaa…\n{noformat}" {
		t.Fatalf("JiraWikiBlock cap = %q", got)
	}
}

// markdownPayloads inject a link, an image, raw HTML, a mention, a team
// mention, an issue reference and an autolink into GitHub markdown.
var markdownPayloads = []string{
	"[Click](https://evil.test/login)",
	"![pixel](https://evil.test/p.png)",
	"<img src=x onerror=alert(1)><details open>hidden</details>",
	"@octocat @org/security-team please look",
	"closes #1 and fixes org/repo#2",
	"https://evil.test/autolink www.evil.test",
	"`code` and ``double`` and ```fence```",
}

func TestMarkdownInline_IsOneCodeSpan(t *testing.T) {
	for _, p := range markdownPayloads {
		got := MarkdownInline(p, MaxInlineRunes)
		run := longestBacktickRun(p) + 1
		fence := strings.Repeat("`", run)
		if !strings.HasPrefix(got, fence+" ") || !strings.HasSuffix(got, " "+fence) {
			t.Errorf("MarkdownInline(%q) = %q is not fenced with %q", p, got, fence)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(got, fence+" "), " "+fence)
		if longestBacktickRun(inner) >= run {
			t.Errorf("MarkdownInline(%q): inner text can close the span", p)
		}
	}
	if MarkdownInline("   ", 10) != "" {
		t.Fatal("blank input should encode to empty")
	}
}

func TestMarkdownBlock_CannotBeClosedEarly(t *testing.T) {
	for _, p := range append(markdownPayloads, "```\n[escaped](https://evil.test)\n```", "````x") {
		got := MarkdownBlock(p+"\u202E", MaxDescriptionRunes)
		lines := strings.Split(got, "\n")
		open := strings.TrimSuffix(lines[0], "text")
		closeFence := lines[len(lines)-1]
		if open != closeFence || len(open) < 3 || strings.Trim(open, "`") != "" {
			t.Fatalf("MarkdownBlock(%q) fences %q / %q", p, open, closeFence)
		}
		inner := strings.Join(lines[1:len(lines)-1], "\n")
		if longestBacktickRun(inner) >= len(open) {
			t.Fatalf("MarkdownBlock(%q): inner text can close the block", p)
		}
		if strings.Contains(inner, "\u202E") {
			t.Fatalf("MarkdownBlock(%q): bidi control kept", p)
		}
	}
}
