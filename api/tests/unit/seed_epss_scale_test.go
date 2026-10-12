package unit

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The demo seed wrote EPSS percentiles as 0–1 fractions while the API (and
// web/src/lib/epss.ts) treat epss_percentile as a 0–100 rank, so every demo
// CVE read "0th percentile" until the EPSS feed overwrote it. Pin the scale.
func TestDemoSeed_EPSSPercentileIsZeroToHundred(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/seed/seed_components_demo.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	start := strings.Index(s, "INSERT INTO vulnerabilities")
	if start < 0 {
		t.Fatal("vulnerabilities insert not found")
	}
	block := s[start : start+strings.Index(s[start:], ";")]

	// Each row carries "  <epss_score>, <epss_percentile>, <kev date|NULL>".
	pair := regexp.MustCompile(`(?m)^\s+(\d+\.\d+|0), (\d+\.\d+|0), (?:'|NULL)`)
	rows := pair.FindAllStringSubmatch(block, -1)
	if len(rows) < 10 {
		t.Fatalf("found %d EPSS rows; the pattern no longer matches the seed", len(rows))
	}
	maxPct := 0.0
	for _, r := range rows {
		score, _ := strconv.ParseFloat(r[1], 64)
		pct, _ := strconv.ParseFloat(r[2], 64)
		if score < 0 || score > 1 {
			t.Errorf("epss_score %v outside 0–1", score)
		}
		if pct < 0 || pct > 100 {
			t.Errorf("epss_percentile %v outside 0–100", pct)
		}
		if pct > maxPct {
			maxPct = pct
		}
	}
	if maxPct <= 1 {
		t.Errorf("every epss_percentile is ≤ 1 (max %v): the seed is on the 0–1 scale again", maxPct)
	}
}
