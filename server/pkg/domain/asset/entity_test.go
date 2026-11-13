package asset

import "testing"

// Technologies are not a property (RFC-112): no write path stores the
// retired key or its input synonym.
func TestRetiredTechnologiesPropertyIsNeverStored(t *testing.T) {
	a, err := NewAsset("www.example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetProperty("technologies", []any{"nginx"})
	a.SetProperty("technology", "nginx")
	a.SetProperties(map[string]any{"technologies": []any{"HSTS"}, "technology": "x", "server": "nginx"})
	props := a.Properties()
	if _, ok := props["technologies"]; ok {
		t.Fatal("technologies stored")
	}
	if _, ok := props["technology"]; ok {
		t.Fatal("technology stored")
	}
	if props["server"] != "nginx" {
		t.Fatalf("other properties lost: %v", props)
	}
}
