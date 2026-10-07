package handler

import (
	"os"
	"regexp"
	"testing"
)

// The scan, scan run and scan workflow lists read `page` and `per_page` only
// through listPage (pagination.FromRequest): one parser, one validation, one
// cap. A handler that parses them itself drifts (a silent default for
// page=abc, a different cap, limit/offset next to page). The rest of the API
// joins this list as its handlers move to the shared parser.
func TestListHandlersUseTheSharedPageParser(t *testing.T) {
	direct := regexp.MustCompile(`Get\("(page|limit|offset|page_size)"\)|parseQuery\w*\(r\.URL\.Query\(\)\.Get\("per_page"\)`)
	for _, file := range []string{"scan_handler.go", "scan_workflow_handler.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if m := direct.Find(src); m != nil {
			t.Errorf("%s reads list paging itself (%s); use listPage", file, m)
		}
	}
}
