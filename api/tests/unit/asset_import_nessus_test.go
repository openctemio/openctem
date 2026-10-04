package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The host-only Nessus import reads the file through the shared Nessus parser
// (one parser per tool, RFC-043): same hosts, same names as before.
func TestAssetImport_Nessus_SharedParser(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := assetapp.NewAssetImportService(repo, logger.NewNop())
	xml := `<?xml version="1.0"?><NessusClientData_v2><Report name="r">
<ReportHost name="10.0.0.5"><HostProperties><tag name="host-ip">10.0.0.5</tag>
<tag name="host-fqdn">web01.corp.example</tag><tag name="operating-system">Linux Kernel 5.4</tag></HostProperties>
<ReportItem port="443" protocol="tcp" pluginID="1" pluginName="x" severity="2"/></ReportHost>
<ReportHost name=""><HostProperties></HostProperties></ReportHost>
</Report></NessusClientData_v2>`
	res, err := svc.ImportNessus(context.Background(), serviceTenantID.String(), strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if res.AssetsCreated != 1 || res.AssetsSkipped != 1 {
		t.Fatalf("created %d skipped %d, want 1 and 1", res.AssetsCreated, res.AssetsSkipped)
	}
	for _, a := range repo.assets {
		if a.Name() != "web01.corp.example" || a.Properties()["ip_address"] != "10.0.0.5" || a.SubType() != "linux" {
			t.Fatalf("asset %s %v %s", a.Name(), a.Properties(), a.SubType())
		}
	}

	if _, err := svc.ImportNessus(context.Background(), serviceTenantID.String(), strings.NewReader("<html/>")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid XML: %v, want a validation error", err)
	}
}
