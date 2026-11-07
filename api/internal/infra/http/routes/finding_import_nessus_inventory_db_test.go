package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
)

// A credentialed Nessus export: two hosts with their installed packages,
// application CPEs, listening sockets and SSH host key. Synthetic:
// documentation addresses, example.com names, made-up packages.
const nessusInventoryDoc = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="inventory">
<ReportHost name="192.0.2.61"><HostProperties>
<tag name="host-ip">192.0.2.61</tag>
<tag name="operating-system">Linux Kernel 6.8.0 on Ubuntu 24.04</tag>
<tag name="cpe-0">cpe:/o:canonical:ubuntu_linux:24.04 -> Canonical Ubuntu Linux 24.04</tag>
<tag name="cpe-1">cpe:/a:examplevendor:example_server:2.4.1 -> Examplevendor Example Server 2.4.1</tag>
<tag name="ssh-fingerprint">ssh-rsa 0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9</tag>
<tag name="netstat-listen-tcp4-0">0.0.0.0:22</tag>
<tag name="netstat-listen-tcp4-1">192.0.2.61:8443 (2211/exampled)</tag>
<tag name="netstat-listen-tcp4-2">127.0.0.1:5432</tag>
</HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0" pluginID="10267" pluginName="SSH Server Type" pluginFamily="Service detection"><description>SSH server.</description></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="22869" pluginName="Software Enumeration (SSH)" pluginFamily="General"><description>Packages.</description><plugin_output>
  ii  examplepkg      2.4.1-1ubuntu2   amd64   Example server package
  ii  libexample1     0.9.3-4          amd64   Example library
</plugin_output></ReportItem>
</ReportHost>
<ReportHost name="192.0.2.62"><HostProperties>
<tag name="host-ip">192.0.2.62</tag>
<tag name="operating-system">Microsoft Windows Server 2022 Standard</tag>
</HostProperties>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="20811" pluginName="Microsoft Windows Installed Software Enumeration (credentialed check)" pluginFamily="Windows"><description>Software.</description><plugin_output>
Example Office Suite  [version 16.0.1]  [installed on 2024/01/15]
</plugin_output></ReportItem>
</ReportHost>
</Report></NessusClientData_v2>`

// Through the Findings-page import: each host gets its own installed
// packages (never another host's), its application CPEs as software, its
// netstat listeners as services marked as seen from inside the host, and
// its SSH host key; nothing lands in another tenant.
func TestFindingImport_NessusHostInventory_DB(t *testing.T) {
	ih := newImportHarness(t, "")
	// The software inventory the server wires: technologies with a CPE
	// become software of the asset.
	ih.ingest.SetSoftwareRepository(postgres.NewSoftwareRepository(&postgres.DB{DB: ih.db}))
	rec, resp := ih.upload(t, ih.tenantID, "", "inventory.nessus", []byte(nessusInventoryDoc), true)
	if rec.Code != http.StatusAccepted || len(resp.Files) != 1 || resp.Files[0].Error != nil {
		t.Fatalf("import %d: %s", rec.Code, rec.Body.String())
	}
	if resp.Files[0].Stats.Components != 3 {
		t.Fatalf("components = %d", resp.Files[0].Stats.Components)
	}
	assetID := func(name string) string {
		t.Helper()
		var id string
		if err := ih.db.QueryRowContext(context.Background(), `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, ih.tenantID, name).Scan(&id); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return id
	}
	linux, windows := assetID("192.0.2.61"), assetID("192.0.2.62")
	pkgs := func(asset string) []string {
		t.Helper()
		rows, err := ih.db.QueryContext(context.Background(), `SELECT p.name FROM asset_software s JOIN software_products p ON p.id = s.product_id
			WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.source = 'package' ORDER BY p.name`, ih.tenantID, asset)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			out = append(out, n)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := strings.Join(pkgs(linux), ","); got != "examplepkg,libexample1" {
		t.Fatalf("linux packages = %q", got)
	}
	if got := strings.Join(pkgs(windows), ","); got != "Example Office Suite" {
		t.Fatalf("windows packages = %q", got)
	}
	// The application CPE is software of the host, so version matching
	// can find its CVEs.
	if n := ih.count(t, `SELECT count(*) FROM asset_software WHERE tenant_id = $1 AND asset_id = $2 AND source <> 'package'`, ih.tenantID, linux); n == 0 {
		t.Fatal("no software from the application CPE")
	}
	// netstat (stored as host:port:transport): 8443 only from inside the host, 22 also reached by the
	// scanner; loopback 5432 is no service.
	view := func(name string) string {
		var v string
		_ = ih.db.QueryRowContext(context.Background(), `SELECT coalesce(properties->>'observed_from', '') FROM assets WHERE tenant_id = $1 AND name = $2`, ih.tenantID, name).Scan(&v)
		return v
	}
	if v := view("192.0.2.61:8443:tcp"); v != "host" {
		t.Fatalf("8443 observed_from = %q", v)
	}
	if v := view("192.0.2.61:22:tcp"); v != "network" {
		t.Fatalf("22 observed_from = %q", v)
	}
	if n := ih.count(t, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = '192.0.2.61:5432:tcp'`, ih.tenantID); n != 0 {
		t.Fatal("a loopback-only socket became a service")
	}
	if n := ih.count(t, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND id = $2 AND properties->'ssh_host_key_fingerprints' ? 'ssh-rsa MD5:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9'`, ih.tenantID, linux); n != 1 {
		t.Fatal("ssh host key not kept")
	}
	// Tenant isolation: no software row of these hosts under another
	// tenant, and no other tenant has these assets.
	if n := ih.count(t, `SELECT count(*) FROM asset_software WHERE tenant_id <> $1 AND asset_id IN ($2, $3)`, ih.tenantID, linux, windows); n != 0 {
		t.Fatalf("%d software rows under another tenant", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM assets WHERE tenant_id <> $1 AND name IN ('192.0.2.61', '192.0.2.62') AND created_at > now() - interval '1 minute'`, ih.tenantID); n != 0 {
		t.Fatalf("%d assets landed in another tenant", n)
	}
}

// An export without plugin details tells the uploader on the import result.
func TestFindingImport_NessusWithoutPluginDetails_DB(t *testing.T) {
	ih := newImportHarness(t, "")
	doc := `<?xml version="1.0"?><NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.63"><HostProperties><tag name="host-ip">192.0.2.63</tag></HostProperties>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="51192" pluginName="Certificate" pluginFamily="General"></ReportItem>
</ReportHost></Report></NessusClientData_v2>`
	rec, resp := ih.upload(t, ih.tenantID, "?dry_run=true", "bare.nessus", []byte(doc), true)
	if rec.Code != http.StatusOK || len(resp.Files) != 1 {
		t.Fatalf("preview %d: %s", rec.Code, rec.Body.String())
	}
	for _, is := range resp.Files[0].Issues {
		if strings.Contains(is.Message, "export lacks plugin details") {
			return
		}
	}
	t.Fatalf("no plugin-details issue: %s", rec.Body.String())
}
