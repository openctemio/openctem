package unit

// Ratchet for the vulnerability catalog seam
// (docs/rfcs/RFC-143-vulnerability-catalog.md, rule R3): code reads the
// vulnerability catalog through vulncatalog.Reader, never through its tables.
// The files below still name a catalog table (readers not yet moved, and the
// feed writers that the catalog builder replaces). The list only shrinks: a
// new file naming a catalog table fails, and so does a listed file that no
// longer names one (remove it from the list).

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var vulnCatalogTableRe = regexp.MustCompile(`\b(cve_records|vulnerability_affected|kev_catalog|epss_scores|` +
	`epss_percentile_curve|epss_score_history|vuln_id_aliases|vuln_events|vuln_event_state|cve_feed_products)\b`)

var vulnCatalogTableFiles = map[string]bool{
	// The reader itself.
	"internal/infra/postgres/vulncatalog_reader.go": true,
	// Not yet behind the reader.
	"internal/app/exposure/enrichment.go":                     true,
	"internal/app/finding/cve_exposure.go":                    true,
	"internal/app/finding/priority_classification.go":         true,
	"internal/app/threat/intel_service.go":                    true,
	"internal/app/vulnevent/emitter.go":                       true,
	"internal/infra/postgres/catalog_stub.go":                 true,
	"internal/infra/postgres/cve_corpus_chunks.go":            true,
	"internal/infra/postgres/cve_corpus_repository.go":        true,
	"internal/infra/postgres/cve_exposure_list_repository.go": true,
	"internal/infra/postgres/cve_exposure_repository.go":      true,
	"internal/infra/postgres/epss_history.go":                 true,
	"internal/infra/postgres/kev_escalation.go":               true,
	"internal/infra/postgres/kev_lookup.go":                   true,
	"internal/infra/postgres/scoring_repository.go":           true,
	"internal/infra/postgres/software_alias_repository.go":    true,
	"internal/infra/postgres/softwarematch_repository.go":     true,
	"internal/infra/postgres/threat_alert_read.go":            true,
	"internal/infra/postgres/threat_alert_repository.go":      true,
	"internal/infra/postgres/threatintel_repository.go":       true,
	"internal/infra/postgres/vulnerability_repository.go":     true,
	"internal/infra/postgres/vuln_event_repository.go":        true,
	"internal/infra/postgres/vuln_id_alias_repository.go":     true,
	"pkg/domain/technology/fields.go":                         true,
	"pkg/domain/vulnerability/epss.go":                        true,
	"pkg/domain/vulnerability/finding_fields.go":              true,
	"pkg/domain/vulnerability/kev.go":                         true,
}

func TestVulnCatalogTablesOnlyBehindTheReader(t *testing.T) {
	const api = "../.."
	found := map[string]bool{}
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		err := filepath.WalkDir(filepath.Join(api, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if vulnCatalogTableRe.Match(b) {
				rel, _ := filepath.Rel(api, path)
				found[filepath.ToSlash(rel)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var added, gone []string
	for f := range found {
		if !vulnCatalogTableFiles[f] {
			added = append(added, f)
		}
	}
	for f := range vulnCatalogTableFiles {
		if !found[f] {
			gone = append(gone, f)
		}
	}
	sort.Strings(added)
	sort.Strings(gone)
	for _, f := range added {
		t.Errorf("%s names a vulnerability catalog table: read it through vulncatalog.Reader", f)
	}
	for _, f := range gone {
		t.Errorf("%s no longer names a vulnerability catalog table: remove it from vulnCatalogTableFiles", f)
	}
}
