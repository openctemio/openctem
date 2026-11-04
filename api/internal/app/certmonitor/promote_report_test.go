package certmonitor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The promotion report is a valid CTIS 2.0 document and carries no OpenCTEM
// id: the tenant comes from the ingest principal, never from the document.
func TestPromotionReport_IsValidCTISWithoutTenantID(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	s := &Service{now: func() time.Time { return now }}
	tenant := shared.NewID()
	first := now.Add(-48 * time.Hour)
	fresh := []string{"api.example.com", "*.wild.example.com", "WWW.Example.com."}
	by := map[string]promotion{
		"api.example.com":    {host: ctHost{Name: "api.example.com", FirstSeen: first}, root: rootDomain{name: "example.com", origin: OriginVerified}, source: "ct"},
		"WWW.Example.com.":   {host: ctHost{Name: "WWW.Example.com.", FirstSeen: first}, root: rootDomain{name: "example.com", origin: OriginVerified}, source: "ct"},
		"*.wild.example.com": {host: ctHost{Name: "*.wild.example.com", FirstSeen: first}, source: "ct"},
	}
	r := s.promotionReport(tenant, fresh, by, promoteKind{technique: "ct_logs", tool: "ct-monitor"})

	if err := r.Validate(); err != nil {
		t.Fatalf("promotion report does not validate: %v", err)
	}
	if !ctis.IsReportID(r.Metadata.ID) || r.Metadata.Channel != ctis.ChannelCollector || r.Metadata.CoverageType != ctis.CoveragePartial {
		t.Fatalf("metadata = %+v", r.Metadata)
	}
	if len(r.Assets) != 2 {
		t.Fatalf("assets = %+v, want the two canonical host names (the wildcard has no CTIS form)", r.Assets)
	}
	for _, a := range r.Assets {
		if a.Type != ctis.AssetTypeDomainName || a.Value != strings.ToLower(strings.TrimSuffix(a.Value, ".")) {
			t.Errorf("asset %+v is not a canonical domain_name", a)
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), tenant.String()) {
		t.Fatal("the report carries the tenant id")
	}
}
