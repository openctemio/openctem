package stage_test

import (
	"testing"

	. "github.com/openctemio/openctem/api/pkg/domain/stage"
)

func TestWebTool(t *testing.T) {
	for tool, want := range map[string]bool{"nuclei": true, " Katana ": true, "toyweb": true, "zap": false, "httpx": false, "naabu": false, "my-tool": false, "": false} {
		if got := cat.WebTool(tool); got != want {
			t.Errorf("cat.WebTool(%q) = %v, want %v", tool, got, want)
		}
	}
}

func TestWebCapability(t *testing.T) {
	for word, want := range map[string]bool{"crawl.web": true, "vuln.templates@1": true, "dast.web": true, "crawler": true,
		"probe.http": false, "web": false, "scan.ports@1": false, "": false} {
		if got := WebCapability(word); got != want {
			t.Errorf("WebCapability(%q) = %v, want %v", word, got, want)
		}
	}
}
