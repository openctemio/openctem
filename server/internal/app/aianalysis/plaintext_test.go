package aianalysis

import (
	"strings"
	"testing"
)

func TestPlainText_NeutralizesMarkup(t *testing.T) {
	cases := map[string]string{
		"![x](https://evil.example/p?q=1)": `\!\[x\]\(https\://evil.example/p?q=1\)`,
		"<img src=x onerror=alert(1)>":     `\<img src=x onerror=alert\(1\)\>`,
		"see www.example.com":              `see www\.example.com`,
		"&#x3C;script&#x3E;":               `\&\#x3C;script\&\#x3E;`,
		"# heading **bold** `code`":        `\# heading \*\*bold\*\* \` + "`" + `code\` + "`",
		"plain words, no markup.":          "plain words, no markup.",
	}
	for in, want := range cases {
		if got := plainText(in); got != want {
			t.Errorf("plainText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlainText_EveryMarkupCharacterEscaped(t *testing.T) {
	got := plainText("[click](javascript:alert(1)) ![img](http://x) <https://a.example> | ~~s~~")
	for i := 0; i < len(got); i++ {
		if strings.ContainsRune("[]()!<>|~", rune(got[i])) && (i == 0 || got[i-1] != '\\') {
			t.Fatalf("unescaped %q at %d in %q", got[i], i, got)
		}
	}
}
