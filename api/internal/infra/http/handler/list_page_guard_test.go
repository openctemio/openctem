package handler

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every list reads its window through one parser: `page` and `per_page`
// through listPage / listPageMax (pagination.FromRequest), a top-N list's
// `limit` through listLimit (pagination.LimitFromRequest). One validation
// (a bad value is a 400, never a silent default) and one cap per list. A
// handler that reads them itself drifts: a silent default for page=abc, a
// different cap, limit/offset next to page.
//
// The reads below are not list paging and are allowed, each with its reason.
var pagingReadAllowed = map[string]string{
	// The audit chain check verifies up to `limit` entries (0: the default
	// window); it is not a list.
	`audit_handler.go:Get("limit")`: "audit chain verification window, not a list",
	// A saved view's `page` names the console page it belongs to.
	`saved_view_handler.go:Get("page")`: "the console page a saved view belongs to",
	// The run tasks list pages by an opaque cursor; per_page sizes it.
	`scan_workflow_handler.go:Get("per_page")`: "cursor-paged run tasks (size of a cursor page)",
	// The sensor protocol's command poll: part of the sensor wire contract.
	`sensor_control_v2_handler.go:Get("limit")`: "sensor protocol v2 poll, a wire contract",
}

func TestListHandlersUseTheSharedPageParser(t *testing.T) {
	direct := regexp.MustCompile(`Get\("(page|limit|offset|page_size|per_page)"\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range direct.FindAll(src, -1) {
			key := file + ":" + string(m)
			if _, ok := pagingReadAllowed[key]; ok {
				used[key] = true
				continue
			}
			t.Errorf("%s reads list paging itself (%s); use listPage, listPageMax or listLimit", file, m)
		}
	}
	for key := range pagingReadAllowed {
		if !used[key] {
			t.Errorf("allowed read %s no longer exists: drop it from pagingReadAllowed", key)
		}
	}
}
