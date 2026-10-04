package nessus

import (
	"errors"
	"strings"
	"testing"
)

const sample = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r">
<ReportHost name="10.0.0.5"><HostProperties>
<tag name="host-ip">10.0.0.5</tag><tag name="host-fqdn">web01.corp.example</tag>
<tag name="operating-system">Linux Kernel 5.4</tag></HostProperties>
<ReportItem port="443" protocol="tcp" svc_name="www" pluginID="12345" pluginName="TLS weak" pluginFamily="General" severity="2">
<cve>CVE-2024-1</cve><cve>CVE-2024-2</cve><cvss3_base_score>5.3</cvss3_base_score></ReportItem>
<ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Scan info" severity="0"/>
</ReportHost></Report></NessusClientData_v2>`

func TestParse(t *testing.T) {
	doc, err := Parse(strings.NewReader(sample), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Hosts) != 1 || len(doc.Hosts[0].Items) != 2 {
		t.Fatalf("parsed %+v", doc)
	}
	h := doc.Hosts[0]
	if p := h.Props(); p["host-fqdn"] != "web01.corp.example" || p["host-ip"] != "10.0.0.5" {
		t.Fatalf("props %v", p)
	}
	it := h.Items[0]
	if it.Port != 443 || it.PluginID != "12345" || len(it.CVEs) != 2 || it.CVSS3Score != "5.3" || it.ServiceName != "www" {
		t.Fatalf("item %+v", it)
	}
}

func TestParse_Errors(t *testing.T) {
	if _, err := Parse(strings.NewReader("<html/>"), 1<<20); !errors.Is(err, ErrInvalid) {
		t.Fatalf("not nessus: %v", err)
	}
	if _, err := Parse(strings.NewReader(sample), 64); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
	// An external entity is not resolved.
	xxe := `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` +
		`<NessusClientData_v2><Report><ReportHost name="&e;"/></Report></NessusClientData_v2>`
	doc, err := Parse(strings.NewReader(xxe), 1<<20)
	if err == nil && len(doc.Hosts) == 1 && strings.Contains(doc.Hosts[0].Name, "root:") {
		t.Fatal("external entity resolved")
	}
}
