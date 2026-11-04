package ingest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// A certificate's text is chosen by the scanned server: capped and cleaned
// on every ingest path, whatever produced the report.
func TestCapReportText_Certificate(t *testing.T) {
	sans := make([]string, 10_000)
	for i := range sans {
		sans[i] = fmt.Sprintf("h%d.example.com", i)
	}
	sans[0] = "evil\n.example.com\x1b[2J"
	ct := &ctis.CertificateTechnical{
		SubjectCN: strings.Repeat("x", 100_000), IssuerCN: "R11\nINFO forged\x00",
		SerialNumber: strings.Repeat("9", 5000), SubjectAltNames: sans,
	}
	rep := &ctis.Report{Assets: []ctis.Asset{{Type: ctis.AssetTypeCertificate, Value: "x", Technical: &ctis.AssetTechnical{Certificate: ct}}}}
	if capReportText(rep) == 0 {
		t.Fatal("nothing capped")
	}
	if n := len([]rune(ct.SubjectCN)); n > MaxCertNameLen {
		t.Errorf("subject CN %d runes", n)
	}
	if len([]rune(ct.SerialNumber)) > MaxCertSerialLen {
		t.Errorf("serial not capped")
	}
	if ct.IssuerCN != "R11INFO forged" {
		t.Errorf("issuer CN = %q", ct.IssuerCN)
	}
	if len(ct.SubjectAltNames) != MaxCertSANs || ct.SubjectAltNames[0] != "evil.example.com[2J" {
		t.Errorf("SANs = %d, first %q", len(ct.SubjectAltNames), ct.SubjectAltNames[0])
	}
}
