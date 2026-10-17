package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// statusListRE finds a hand-written SQL status list: status IN ('a', 'b') or
// status NOT IN (...), any table alias.
var statusListRE = regexp.MustCompile(`(?i)\bstatus\s+(NOT\s+)?IN\s*\(\s*('[a-z_]+'(?:\s*,\s*'[a-z_]+')*)\s*\)`)

// handWrittenStatusListAllowed are the few finding-status lists that are not
// an open / fixed / dispositioned / closed definition, keyed by file (relative
// to api/) and the exact list. Each says why it is its own set. Everything
// else uses vulnerability.OpenStatusSQL and its siblings.
var handWrittenStatusListAllowed = map[string]map[string]string{
	"internal/infra/postgres/pentest_campaign_stats.go": {
		"status NOT IN ('draft', 'in_review', 'false_positive', 'duplicate')": "a pentest report's published findings (publication, not lifecycle)",
		"status IN ('confirmed', 'in_progress')":                              "the pentest 'being fixed' work bucket next to fix_applied",
	},
	"internal/infra/postgres/dashboard_program_metrics.go": {
		"status NOT IN ('false_positive', 'duplicate')": "mean time to validate population: every real finding, open or closed",
	},
}

// TestNoHandWrittenFindingStatusLists fails when Go code hand-writes a SQL list
// of finding statuses (two or more) instead of using the one shared definition
// in pkg/domain/vulnerability/status_sets.go. Lists of other tables' statuses
// (commands, scan runs, approvals) and lists of only the pentest pre-publication
// statuses are not finding-lifecycle definitions and are ignored.
func TestNoHandWrittenFindingStatusLists(t *testing.T) {
	findingStatuses := map[string]bool{}
	for _, s := range vulnerability.AllFindingStatuses() {
		findingStatuses[string(s)] = true
	}
	prePublication := map[string]bool{
		string(vulnerability.FindingStatusDraft):    true,
		string(vulnerability.FindingStatusInReview): true,
	}
	apiRoot := filepath.Join("..", "..", "..")
	seenAllowed := map[string]bool{}
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		err := filepath.WalkDir(filepath.Join(apiRoot, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(apiRoot, path)
			rel = filepath.ToSlash(rel)
			for _, m := range statusListRE.FindAllStringSubmatchIndex(string(src), -1) {
				text := string(src[m[0]:m[1]])
				members := regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(string(src[m[4]:m[5]]), -1)
				if len(members) < 2 {
					continue
				}
				allFinding, allPrePub := true, true
				for _, mem := range members {
					allFinding = allFinding && findingStatuses[mem[1]]
					allPrePub = allPrePub && prePublication[mem[1]]
				}
				if !allFinding || allPrePub {
					continue
				}
				if _, ok := handWrittenStatusListAllowed[rel][text]; ok {
					seenAllowed[rel+"|"+text] = true
					continue
				}
				line := strings.Count(string(src[:m[0]]), "\n") + 1
				t.Errorf("%s:%d hand-writes a finding status list %q: use vulnerability.OpenStatusSQL, "+
					"FixedStatusSQL, DispositionedStatusSQL or ClosedStatusSQL (status_sets.go), "+
					"or add it to handWrittenStatusListAllowed with the reason it is a different set", rel, line, text)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	for file, lists := range handWrittenStatusListAllowed {
		for text := range lists {
			if !seenAllowed[file+"|"+text] {
				t.Errorf("stale allow-list entry %s %q: remove it", file, text)
			}
		}
	}
}
