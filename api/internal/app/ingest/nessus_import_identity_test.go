package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A .nessus upload is converted by the ctis importer. Every plugin result,
// port-level or host-level (port 0), keeps the network identity a Nessus
// finding has always had here: (host asset, CVE or plugin, port/protocol or
// "host"). Findings stored by earlier uploads are therefore updated, not
// duplicated.
func TestNessusImport_NetworkIdentity(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.5"><HostProperties><tag name="host-ip">192.0.2.5</tag></HostProperties>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="98765" pluginName="Heartbleed" pluginFamily="General"><cve>CVE-2014-0346</cve><cve>CVE-2014-0160</cve></ReportItem>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="70658" pluginName="SSH CBC" pluginFamily="Misc."/>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="2" pluginID="57582" pluginName="Self-signed" pluginFamily="General"/>
<ReportItem port="0" svc_name="general" protocol="icmp" severity="1" pluginID="10114" pluginName="ICMP timestamp" pluginFamily="General"><cve>CVE-1999-0524</cve></ReportItem>
</ReportHost></Report></NessusClientData_v2>`
	res, err := importer.Parse(context.Background(), strings.NewReader(doc), importer.Options{ReportID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	asset := shared.NewID()
	want := []struct {
		vuln, rule string
		port       int
		proto      string
	}{
		{"CVE-2014-0160", "98765", 443, "tcp"},
		{"", "70658", 22, "tcp"},
		{"", "57582", 0, "tcp"},
		{"CVE-1999-0524", "10114", 0, "icmp"},
	}
	if len(res.Report.Findings) != len(want) {
		t.Fatalf("findings = %d", len(res.Report.Findings))
	}
	for i, w := range want {
		f := &res.Report.Findings[i]
		got, ok := identityV2(asset, f, res.Report.Tool, "", 0)
		if !ok {
			t.Fatalf("finding %d (%s): no identity", i, f.RuleID)
		}
		exp, _ := vulnerability.NetworkIdentity(asset.String(), w.vuln, w.rule, w.port, w.proto)
		if got.Fingerprint() != exp.Fingerprint() {
			t.Errorf("finding %d (%s): identity %s, want the network identity %s", i, f.RuleID, got.Fingerprint(), exp.Fingerprint())
		}
	}
}
