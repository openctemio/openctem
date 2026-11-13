package markdown

import (
	"strings"
	"testing"
)

func TestHTML_EscapesAndFormats(t *testing.T) {
	md := "Hello **bold** <script>alert(1)</script> and `code`\n\n- one\n- two\n\n```\n<b>x</b>\n```\n\n[click](javascript:alert(1)) [docs](https://example.com)"
	out := HTML(md, nil)
	for _, bad := range []string{"<script>", "javascript:", "<b>x</b>"} {
		if strings.Contains(out, bad) {
			t.Fatalf("unsafe output %q in %s", bad, out)
		}
	}
	for _, want := range []string{"<strong>bold</strong>", "&lt;script&gt;", "<code>code</code>", "<ul><li>one</li><li>two</li></ul>", "<pre><code>&lt;b&gt;x&lt;/b&gt;</code></pre>", `<a href="https://example.com" rel="noopener noreferrer">docs</a>`, "click"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestHTML_ImagesOnlyWhenResolved(t *testing.T) {
	md := "![shot](/api/v1/attachments/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa) ![remote](https://tracker.example/p.png)"
	out := HTML(md, map[string]Image{"/api/v1/attachments/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": {ContentType: "image/png", Data: []byte{1, 2, 3}, Width: 1, Height: 1}})
	if !strings.Contains(out, `src="data:image/png;base64,AQID"`) {
		t.Fatalf("resolved image not embedded: %s", out)
	}
	if strings.Contains(out, "tracker.example") || !strings.Contains(out, "[remote]") {
		t.Fatalf("an unresolved image must render as its alt text: %s", out)
	}
}

func TestImageURLs(t *testing.T) {
	got := ImageURLs("![a](/x) text ![b](/y) ![a2](/x)")
	if len(got) != 2 || got[0] != "/x" || got[1] != "/y" {
		t.Fatalf("got %v", got)
	}
}

func TestParse_SnakeCaseIsNotItalic(t *testing.T) {
	blocks := Parse("call get_user_by_id now")
	if len(blocks) != 1 || len(blocks[0].Inlines) != 1 || blocks[0].Inlines[0].Italic {
		t.Fatalf("snake_case parsed as emphasis: %+v", blocks)
	}
}
