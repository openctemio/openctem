package handler

import "testing"

// Two findings of one issue on two assets get two display titles; the stored
// title stays the issue, and the export carries both plus the asset columns.
func TestSetDisplayTitle_TargetFromAssetAndPort(t *testing.T) {
	a := FindingResponse{Title: "CVE-2019-9516 in nginx 1.15.5", NetworkPort: 443, Asset: &FindingAssetInfo{Name: "10.20.30.41"}}
	b := FindingResponse{Title: "CVE-2019-9516 in nginx 1.15.5", NetworkPort: 8443, Asset: &FindingAssetInfo{Name: "edge-01.shop.example.com"}}
	setDisplayTitle(&a)
	setDisplayTitle(&b)
	if a.DisplayTitle != "CVE-2019-9516 in nginx 1.15.5 on 10.20.30.41:443" {
		t.Fatalf("a: %q", a.DisplayTitle)
	}
	if b.DisplayTitle != "CVE-2019-9516 in nginx 1.15.5 on edge-01.shop.example.com:8443" {
		t.Fatalf("b: %q", b.DisplayTitle)
	}
	if a.Title != b.Title {
		t.Fatal("the stored title must not change")
	}
	row := toFindingExportRow(a)
	if row.DisplayTitle != a.DisplayTitle || row.Title != a.Title || row.AssetName != "10.20.30.41" {
		t.Fatalf("export row: %+v", row)
	}
}

// No readable asset (lookup failed, or the asset is outside the caller's
// tenant): the display title names no asset, only what the finding carries.
func TestSetDisplayTitle_NoAssetNamesNoAsset(t *testing.T) {
	r := FindingResponse{Title: "Weak cipher", NetworkPort: 443}
	setDisplayTitle(&r)
	if r.DisplayTitle != "Weak cipher" {
		t.Fatalf("got %q", r.DisplayTitle)
	}
	u := FindingResponse{Message: "Exposed .git", FilePath: "https://portal.example.com/.git/config"}
	setDisplayTitle(&u)
	if u.DisplayTitle != "Exposed .git on https://portal.example.com/.git/config" {
		t.Fatalf("URL target: %q", u.DisplayTitle)
	}
}
