package component

import (
	"reflect"
	"testing"
)

func TestShortestPaths(t *testing.T) {
	// app -> lib -> util, app -> util, other -> util; lib <-> util cycle.
	up := map[string][]string{
		"lib":  {"app", "util"},
		"util": {"app", "lib", "other"},
	}
	paths := ShortestPaths([]string{"util"}, up, MaxGraphDepth, 10)
	if len(paths) < 3 {
		t.Fatalf("paths = %v", paths)
	}
	if !reflect.DeepEqual(paths[0], []string{"app", "util"}) || !reflect.DeepEqual(paths[1], []string{"other", "util"}) {
		t.Fatalf("shortest first: %v", paths)
	}
	if !reflect.DeepEqual(paths[2], []string{"app", "lib", "util"}) {
		t.Fatalf("third path = %v", paths[2])
	}
	if got := ShortestPaths([]string{"util"}, up, MaxGraphDepth, 1); len(got) != 1 {
		t.Fatalf("limit: %v", got)
	}
	if got := ShortestPaths([]string{"root"}, up, MaxGraphDepth, 5); !reflect.DeepEqual(got, [][]string{{"root"}}) {
		t.Fatalf("a root is its own path: %v", got)
	}
}

func TestDescendAndNeighbourhood(t *testing.T) {
	down := map[string][]string{"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": {"a"}}
	up := map[string][]string{"b": {"a"}, "c": {"a"}, "d": {"b", "c"}, "a": {"d"}}
	ids, edges, truncated := Descend([]string{"a"}, down, MaxGraphDepth, MaxGraphNodes)
	if len(ids) != 4 || len(edges) != 5 || truncated {
		t.Fatalf("descend = %v %v %v", ids, edges, truncated)
	}
	if ids, _, truncated := Descend([]string{"a"}, down, 1, MaxGraphNodes); len(ids) != 3 || !truncated {
		t.Fatalf("depth bound = %v %v", ids, truncated)
	}
	if ids, _, truncated := Descend([]string{"a"}, down, MaxGraphDepth, 2); len(ids) != 2 || !truncated {
		t.Fatalf("node bound = %v %v", ids, truncated)
	}
	ids, edges, _ = Neighborhood([]string{"b"}, down, up, 1, MaxGraphNodes)
	if len(ids) != 3 || len(edges) != 3 {
		t.Fatalf("neighborhood = %v %v", ids, edges)
	}
}

func TestVersions(t *testing.T) {
	if got := SortVersions([]string{"1.10.0", "1.2.0", "1.2.0", "v1.9", "2.0.0, 1.0.1"}); !reflect.DeepEqual(got, []string{"1.0.1", "1.2.0", "v1.9", "1.10.0", "2.0.0"}) {
		t.Fatalf("sort = %v", got)
	}
	cases := []struct {
		current string
		fixed   []string
		want    *UpgradeAdvice
	}{
		{"4.17.20", []string{"4.17.21"}, &UpgradeAdvice{Version: "4.17.21", Complete: true}},
		{"7.0.3", []string{"6.0.6", "7.0.5"}, &UpgradeAdvice{Version: "7.0.5", Complete: true}},
		{"2.14.1", []string{"2.15.0", "2.16.0", "2.17.1"}, &UpgradeAdvice{Version: "2.17.1", Complete: true}},
		{"1.2.0", []string{"2.0.1", "3.0.0"}, &UpgradeAdvice{Version: "2.0.1", Breaking: true, Complete: true}},
		{"1.2.0", []string{"2.0.1", "2.0.3"}, &UpgradeAdvice{Version: "2.0.1", Breaking: true, Complete: false}},
		{"5.0.0", []string{"4.0.1"}, nil},
		{"5.0.0", nil, nil},
	}
	for _, c := range cases {
		got := AdviseUpgrade(c.current, c.fixed, true)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("AdviseUpgrade(%s, %v) = %+v, want %+v", c.current, c.fixed, got, c.want)
		}
	}
	if AdviseUpgrade("1.0.0", []string{"1.0.1"}, false) != nil {
		t.Error("no advice without open findings")
	}
}
