package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

func TestSanitizeHTTPPosture(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{
		{Type: ctis.AssetTypeHTTPService, Value: "https://a.example.com", Properties: ctis.Properties{
			webendpoint.PostureKey: map[string]any{"hsts": true, "set_cookie": "sid=SECRET", "cookies": []any{map[string]any{"name": "sid", "secure": true, "value": "SECRET"}}}}},
		{Type: ctis.AssetTypeHTTPService, Value: "https://b.example.com", Properties: ctis.Properties{
			webendpoint.PostureKey: map[string]any{"only_unknown": "SECRET"}}},
		{Type: ctis.AssetTypeHTTPService, Value: "https://c.example.com"}, // an older producer: no posture
		{Type: ctis.AssetTypeDomain, Value: "example.com", Properties: ctis.Properties{webendpoint.PostureKey: map[string]any{"hsts": true}}},
	}}
	sanitizeHTTPPosture(r)
	b, _ := json.Marshal(r.Assets)
	if strings.Contains(string(b), "SECRET") {
		t.Fatalf("a value was kept: %s", b)
	}
	if r.Assets[0].Properties[webendpoint.PostureKey].(map[string]any)["hsts"] != true {
		t.Fatalf("allow-listed key lost: %s", b)
	}
	for _, i := range []int{1, 3} {
		if _, ok := r.Assets[i].Properties[webendpoint.PostureKey]; ok {
			t.Fatalf("asset %d kept a posture it must not", i)
		}
	}
	if r.Assets[2].Properties != nil {
		t.Fatal("absence must change nothing")
	}
	sanitizeHTTPPosture(nil)
}
