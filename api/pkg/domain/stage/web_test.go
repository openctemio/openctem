package stage

import "testing"

func TestWebTool(t *testing.T) {
	for tool, want := range map[string]bool{"nuclei": true, " Katana ": true, "zap": true, "httpx": false, "naabu": false, "my-tool": false, "": false} {
		if got := WebTool(tool); got != want {
			t.Errorf("WebTool(%q) = %v, want %v", tool, got, want)
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
