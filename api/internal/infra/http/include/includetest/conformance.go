// Package includetest is the include= conformance suite (the rules in
// docs/architecture/tool-availability.md, "include="):
// every resource that registers includes runs RunConformance from its
// DB-backed route test, against the real router and database.
package includetest

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/include"
)

// Fixture describes one resource to the suite.
type Fixture struct {
	Registry *include.Registry
	// Get performs a GET as principal ("full" or "bare") and returns the
	// status, the headers and the body.
	Get func(t *testing.T, principal, path string) (int, http.Header, string)
	// ListPath is the list route; ItemPath one parent the callers may read;
	// ForeignItemPath a parent of another tenant (404 with any include).
	ListPath, ItemPath, ForeignItemPath string
	// ItemsKey names the list's array ("items").
	ItemsKey string
	// AllowedKeys is, per include, the keys the included object may carry
	// (the projection's allow-list).
	AllowedKeys map[string][]string
}

// Principals the fixture's Get understands.
const (
	// Full holds every include's permissions.
	Full = "full"
	// Bare holds the parent's read permission only.
	Bare = "bare"
)

func withQuery(path, q string) string {
	if strings.Contains(path, "?") {
		return path + "&" + q
	}
	return path + "?" + q
}

// RunConformance runs every rule against the resource.
func RunConformance(t *testing.T, f Fixture) {
	t.Helper()
	names := make([]string, 0, len(f.Registry.Specs()))
	for _, s := range f.Registry.Specs() {
		names = append(names, s.Name)
	}
	t.Run("refuses_unknown_nested_too_many_too_long", func(t *testing.T) { refusesInvalid(t, f, names) })
	t.Run("missing_permission_omits_and_lists", func(t *testing.T) {
		for _, n := range names {
			omitsWithoutPermission(t, f, n)
		}
	})
	t.Run("granted_include_projection_and_no_store", func(t *testing.T) {
		for _, n := range names {
			grantedProjection(t, f, n)
		}
	})
	t.Run("expensive_include_caps_page", func(t *testing.T) { capsExpensivePage(t, f) })
	t.Run("cross_tenant_parent_not_found", func(t *testing.T) {
		code, _, body := f.Get(t, Full, withQuery(f.ForeignItemPath, "include="+strings.Join(names, ",")))
		if code != http.StatusNotFound {
			t.Errorf("another tenant's parent with every include: %d %s, want 404", code, body)
		}
	})
}

func refusesInvalid(t *testing.T, f Fixture, names []string) {
	t.Helper()
	bad := []string{
		"include=not_offered",
		"include=" + names[0] + ".sub",
		"include=" + strings.Repeat(names[0]+",", include.MaxIncludes) + names[0],
		"include=" + strings.Repeat("x", 65),
	}
	for _, q := range bad {
		for _, p := range []string{f.ListPath, f.ItemPath} {
			code, _, body := f.Get(t, Full, withQuery(p, q))
			if code != http.StatusBadRequest || !strings.Contains(body, `"INVALID_INCLUDE"`) {
				t.Errorf("%s: %d %s, want 400 INVALID_INCLUDE", withQuery(p, q), code, body)
			}
		}
	}
}

// omitsWithoutPermission: 200, the include absent and named, on the list and
// on one item alike (the omission does not depend on related data).
func omitsWithoutPermission(t *testing.T, f Fixture, n string) {
	t.Helper()
	listOmitted, items := listRead(t, f, Bare, n)
	for _, it := range items {
		if _, present := it[n]; present {
			t.Fatalf("include=%s without permission: the list carries it", n)
		}
	}
	item := itemRead(t, f, Bare, n)
	if _, present := item[n]; present {
		t.Fatalf("item include=%s without permission: present", n)
	}
	if !slices.Contains(listOmitted, n) || !slices.Contains(omittedOf(item), n) {
		t.Fatalf("include=%s: omitted list %v / item %v, want it named in both", n, listOmitted, omittedOf(item))
	}
}

// grantedProjection: present, keys within the allow-list, private no-store.
func grantedProjection(t *testing.T, f Fixture, n string) {
	t.Helper()
	code, hdr, body := f.Get(t, Full, withQuery(f.ItemPath, "include="+n))
	if code != http.StatusOK {
		t.Fatalf("item include=%s: %d %s", n, code, body)
	}
	if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") || !strings.Contains(cc, "private") {
		t.Errorf("include=%s: Cache-Control %q, want private, no-store", n, cc)
	}
	var item map[string]any
	_ = json.Unmarshal([]byte(body), &item)
	sub, ok := item[n].(map[string]any)
	if !ok {
		t.Fatalf("include=%s granted but absent: %s", n, body)
	}
	for k := range sub {
		if !slices.Contains(f.AllowedKeys[n], k) {
			t.Errorf("include=%s carries key %q outside its allow-list %v", n, k, f.AllowedKeys[n])
		}
	}
	if omitted := omittedOf(item); len(omitted) != 0 {
		t.Errorf("include=%s granted, yet omitted %v", n, omitted)
	}
}

func capsExpensivePage(t *testing.T, f Fixture) {
	t.Helper()
	for _, s := range f.Registry.Specs() {
		if !s.Expensive {
			continue
		}
		code, _, body := f.Get(t, Full, withQuery(f.ListPath, "per_page=1000&include="+s.Name))
		var page struct {
			PerPage int `json:"per_page"`
		}
		_ = json.Unmarshal([]byte(body), &page)
		if code != http.StatusOK || page.PerPage != include.ExpensivePerPage {
			t.Errorf("include=%s per_page=1000: %d per_page %d, want %d", s.Name, code, page.PerPage, include.ExpensivePerPage)
		}
	}
}

func itemRead(t *testing.T, f Fixture, principal, inc string) map[string]any {
	t.Helper()
	code, _, body := f.Get(t, principal, withQuery(f.ItemPath, "include="+inc))
	if code != http.StatusOK {
		t.Fatalf("item include=%s as %s: %d %s", inc, principal, code, body)
	}
	var item map[string]any
	_ = json.Unmarshal([]byte(body), &item)
	return item
}

func listRead(t *testing.T, f Fixture, principal, inc string) ([]string, []map[string]any) {
	t.Helper()
	code, _, body := f.Get(t, principal, withQuery(f.ListPath, "include="+inc))
	if code != http.StatusOK {
		t.Fatalf("list include=%s as %s: %d %s", inc, principal, code, body)
	}
	var page map[string]any
	_ = json.Unmarshal([]byte(body), &page)
	raw, _ := page[f.ItemsKey].([]any)
	items := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			items = append(items, m)
		}
	}
	return omittedOf(page), items
}

func omittedOf(obj map[string]any) []string {
	meta, _ := obj["meta"].(map[string]any)
	list, _ := meta["omitted_includes"].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
