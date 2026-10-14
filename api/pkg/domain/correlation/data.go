// Package correlation decides when findings of different rules are one
// issue (research/134 section 12). Correlation may reduce noise, never
// coverage: only the tiers proven safe change a status (and every change is
// reversible); anything less certain is a "possibly related" suggestion a
// person confirms. The framework is generic; DAST is the first kind.
package correlation

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed dast.json
var dastData []byte

// DASTData is the data the DAST correlator reads: payload hosts and CWE
// lists, held as data, not code.
type DASTData struct {
	OASTHosts     []string `json:"oast_hosts"`
	InjectionCWEs []string `json:"injection_cwes"`
	BroadCWEs     []string `json:"broad_cwes"`
}

var (
	dataOnce sync.Once
	data     DASTData
	oast     map[string]bool
	inject   map[string]bool
)

func load() {
	dataOnce.Do(func() {
		if err := json.Unmarshal(dastData, &data); err != nil {
			panic("correlation: dast.json: " + err.Error())
		}
		oast, inject = map[string]bool{}, map[string]bool{}
		for _, h := range data.OASTHosts {
			oast[strings.ToLower(h)] = true
		}
		for _, c := range data.InjectionCWEs {
			inject[NormalizeCWE(c)] = true
		}
	})
}

// Data returns the DAST correlation data.
func Data() DASTData { load(); return data }

// IsOASTHost reports whether host is, or is under, a listed payload domain
// or one of the extra hosts (a configured interactsh server).
func IsOASTHost(host string, extra ...string) bool {
	load()
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, x := range extra {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" && (h == x || strings.HasSuffix(h, "."+x)) {
			return true
		}
	}
	for d := range oast {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// IsInjectionCWE reports whether a (normalized) CWE may auto-merge.
func IsInjectionCWE(cwe string) bool { load(); return inject[NormalizeCWE(cwe)] }

// NormalizeCWE writes a CWE as "CWE-<n>" (upper case, trimmed).
func NormalizeCWE(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	if c != "" && !strings.HasPrefix(c, "CWE-") && !strings.HasPrefix(c, "NVD-") {
		c = "CWE-" + c
	}
	return c
}
