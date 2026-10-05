package postgres

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// research/22 P0-13 (22b I7): the EASM summary counts only exposure types
// something writes. Each listed type must be referenced by non-test code in
// internal/app (by its exposure.EventType constant or its literal).
func TestEASMExposureTypesHaveProducers(t *testing.T) {
	constOf := map[string]string{
		"subdomain_discovered": "EventTypeSubdomainDiscovered", "certificate_expiring": "EventTypeCertificateExpiring",
		"certificate_expired": "EventTypeCertificateExpired", "port_open": "EventTypePortOpen",
		"service_detected": "EventTypeServiceDetected", "ssl_issue": "EventTypeSSLIssue",
		"dangling_cname": "EventTypeDanglingCNAME", "dangling_ns": "EventTypeDanglingNS",
		"email_security_weak": "EventTypeEmailSecurityWeak", "subdomain_takeover": "EventTypeSubdomainTakeover",
	}
	var src strings.Builder
	err := filepath.WalkDir("../../app", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		src.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	code := src.String()
	for _, typ := range EASMExposureTypes {
		c, ok := constOf[typ]
		if !ok {
			t.Errorf("%s: add its constant here once something produces it", typ)
			continue
		}
		if !strings.Contains(code, "exposuredom."+c) && !strings.Contains(code, "exposure."+c) && !strings.Contains(code, `"`+typ+`"`) {
			t.Errorf("%s is counted by the EASM summary but nothing in internal/app produces it", typ)
		}
	}
}
