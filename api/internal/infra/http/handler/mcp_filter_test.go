package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// list_findings' filter param: the search box syntax, ANDed with the
// params, through the findings list's own registry.
func TestMCP_ListFindingsFilter(t *testing.T) {
	fr := &fakeFindingReader{}
	h := NewMCPHandler(fr, nil, nil, nil, nil, nil, nil, logger.NewNop())
	if _, refused := toolPayload(t, h, "list_findings", `{"status":"new","filter":"severity>=high -source:pentest"}`); refused != "" {
		t.Fatalf("refused: %s", refused)
	}
	got := leafText(fr.gotListSpec)
	for _, want := range []string{"status:in:new", "severity:in:critical,high", "source:not_in:pentest"} {
		if !strings.Contains(got, want) {
			t.Errorf("spec %q lacks %q", got, want)
		}
	}
	// A bad or forbidden field, and a parse error, are refused before any
	// read, without echoing values.
	for _, f := range []string{`nosuchfield=zzsecretzz`, `severity=zzsecretzz`, `(severity=high`, `tenant_id=zzsecretzz`} {
		fr := &fakeFindingReader{}
		h := NewMCPHandler(fr, nil, nil, nil, nil, nil, nil, logger.NewNop())
		_, refused := toolPayload(t, h, "list_findings", `{"filter":"`+strings.ReplaceAll(f, `"`, `\"`)+`"}`)
		if refused == "" || strings.Contains(refused, "zzsecretzz") || fr.gotListSpec != nil {
			t.Errorf("filter %q: refused %q, read %v", f, refused, fr.gotListSpec != nil)
		}
	}
}
