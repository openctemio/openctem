package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func boundReport(capRef string) *ctis.Report {
	r := &ctis.Report{}
	setReportCapability(r, capRef)
	return r
}

// The source comes from the capability the platform bound the report to.
func TestServiceKindEvidence(t *testing.T) {
	cases := map[string]asset.KindSource{
		"detect.services@1": asset.KindSourceFingerprint,
		"check.tls@1":       asset.KindSourceTLSALPN,
		"probe.http@1":      asset.KindSourceHTTPProbe,
		"scan.ports@1":      asset.KindSourceReported,
		"":                  asset.KindSourceReported,
	}
	for ref, want := range cases {
		if got := serviceKindEvidence(boundReport(ref)); got != want {
			t.Errorf("%q: %s, want %s", ref, got, want)
		}
	}
	if got := serviceKindEvidence(nil); got != asset.KindSourceReported {
		t.Errorf("nil report: %s", got)
	}
}

func openPort(t *testing.T) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithSubType("203.0.113.5:6379:tcp", asset.AssetTypeService, "open_port", asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetProperties(map[string]any{"port": 6379, "transport": "tcp"})
	return a
}

func kindSvcAsset(proto string) *ctis.Asset {
	return &ctis.Asset{Type: ctis.AssetTypeService, Value: "203.0.113.5:6379/tcp",
		Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: 6379, Transport: ctis.TransportTCP, AppProtocol: proto}}}
}

// A port scan gives a guess; detection replaces it; a later port scan never
// downgrades it.
func TestClassifyReportedService_Precedence(t *testing.T) {
	a := openPort(t)
	classifyReportedService(a, kindSvcAsset(""), asset.KindSourceReported)
	if k, src := asset.ServiceKindOf(a.Properties()); k != "redis" || src != asset.KindSourcePortGuess {
		t.Fatalf("port scan: %s %s", k, src)
	}
	classifyReportedService(a, kindSvcAsset("redis"), asset.KindSourceFingerprint)
	if k, src := asset.ServiceKindOf(a.Properties()); k != "redis" || src != asset.KindSourceFingerprint {
		t.Fatalf("detection: %s %s", k, src)
	}
	classifyReportedService(a, kindSvcAsset(""), asset.KindSourceReported)
	if _, src := asset.ServiceKindOf(a.Properties()); src != asset.KindSourceFingerprint {
		t.Fatalf("a port scan downgraded a fingerprint: %s", src)
	}
	// A pushed report naming another protocol is below a fingerprint.
	classifyReportedService(a, kindSvcAsset("telnet"), asset.KindSourceReported)
	if k, _ := asset.ServiceKindOf(a.Properties()); k != "redis" {
		t.Fatalf("a report overwrote a fingerprint: %s", k)
	}
}

// A report can never set the derived keys through properties.
func TestBuildPropertiesFromCTIS_DropsServiceKindKeys(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	ca := kindSvcAsset("")
	ca.Properties = map[string]any{"service_kind": "modbus", "service_category": "industrial_ot", "kind_source": "fingerprint"}
	props := p.buildPropertiesFromCTIS(ca)
	for _, k := range []string{"service_kind", "service_category", "kind_source"} {
		if _, ok := props[k]; ok {
			t.Errorf("report-supplied %s kept", k)
		}
	}
	a := openPort(t)
	p.mergeCTISIntoAsset(a, ca, nil, time.Time{}, nil)
	classifyReportedService(a, ca, asset.KindSourceReported)
	if k, src := asset.ServiceKindOf(a.Properties()); k != "redis" || src != asset.KindSourcePortGuess {
		t.Fatalf("forged kind reached the asset: %s %s", k, src)
	}
}

// Only a measured anonymous access is recorded.
func TestBuildServiceProperties_AnonymousAccess(t *testing.T) {
	if _, ok := buildServiceProperties(&ctis.ServiceTechnical{Port: 6379})[asset.PropKeyHasAnonymousAccess]; ok {
		t.Error("unmeasured anonymous access recorded")
	}
	if buildServiceProperties(&ctis.ServiceTechnical{Port: 6379, HasAnonymousAccess: true})[asset.PropKeyHasAnonymousAccess] != true {
		t.Error("measured anonymous access dropped")
	}
}
