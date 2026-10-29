package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestCVEListOrderBy(t *testing.T) {
	got, err := cveListOrderBy(vulnerability.CVEListSort{Key: vulnerability.CVEListSortRisk})
	if err != nil {
		t.Fatal(err)
	}
	want := "r.prio_rank ASC NULLS LAST, r.kev DESC NULLS LAST, (r.em_id IS NOT NULL) DESC NULLS LAST, " +
		"r.epss DESC NULLS LAST, r.cvss DESC NULLS LAST, r.assets DESC NULLS LAST, r.cve_id ASC"
	if got != want {
		t.Errorf("risk order\n got %s\nwant %s", got, want)
	}
	flipped, _ := cveListOrderBy(vulnerability.CVEListSort{Key: vulnerability.CVEListSortEPSS, Flipped: true})
	if flipped != "r.epss ASC NULLS LAST, r.cve_id ASC" {
		t.Errorf("flipped epss = %s", flipped)
	}
	cve, _ := cveListOrderBy(vulnerability.CVEListSort{Key: vulnerability.CVEListSortCVE, Flipped: true})
	if cve != "r.cve_id DESC" {
		t.Errorf("-cve = %s", cve)
	}
	if _, err := cveListOrderBy(vulnerability.CVEListSort{Key: "x; DROP TABLE findings"}); err == nil {
		t.Error("an unknown key must not reach SQL")
	}
	// Every key the domain accepts has SQL.
	for _, k := range []string{"risk", "cvss", "epss", "assets", "findings", "first_seen", "last_seen", "kev_due", "cve"} {
		if s, err := cveListOrderBy(vulnerability.CVEListSort{Key: k}); err != nil || !strings.HasSuffix(s, "r.cve_id ASC") {
			t.Errorf("key %s: %q %v", k, s, err)
		}
	}
}

func TestAddCVEListProduct_Bounds(t *testing.T) {
	it := &vulnerability.CVEListItem{}
	addCVEListProduct(it, "openssl", "3.0.1", 4)
	addCVEListProduct(it, "openssl", "3.0.2", 1)
	addCVEListProduct(it, "zlib", "", 2)
	addCVEListProduct(it, "curl", "8.0", 1)
	addCVEListProduct(it, "expat", "2.5", 1)
	if len(it.Products) != vulnerability.MaxCVEListProducts {
		t.Fatalf("products = %d, want %d", len(it.Products), vulnerability.MaxCVEListProducts)
	}
	if p := it.Products[0]; p.Name != "openssl" || p.Findings != 5 || strings.Join(p.Versions, ",") != "3.0.1,3.0.2" {
		t.Errorf("openssl = %+v", p)
	}
	if p := it.Products[1]; p.Name != "zlib" || len(p.Versions) != 0 {
		t.Errorf("zlib = %+v (an empty version is not listed)", p)
	}
}
