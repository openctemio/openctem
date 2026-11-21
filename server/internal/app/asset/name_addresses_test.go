package asset

import (
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
)

// One row per address over every source: first seen the earliest, last seen
// the latest, current while any source reports it, removed the latest
// removal otherwise; shared provider addresses carry the provider; current
// addresses first; other attributes ignored.
func TestFoldNameAddresses(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	at := func(d int) time.Time { return t0.AddDate(0, 0, d) }
	gone := func(d int) *time.Time { v := at(d); return &v }
	ip := assetdom.SetAttrIPAddresses
	rows := []assetdom.SetElement{
		{Attribute: ip, Kind: assetdom.SourceKindScan, Name: "dnsx", Element: "13.107.128.10", FirstSeen: at(2), LastSeen: at(5), RemovedAt: gone(6)},
		{Attribute: ip, Kind: assetdom.SourceKindScan, Name: "httpx", Element: "13.107.128.10", FirstSeen: at(1), LastSeen: at(9)},
		{Attribute: ip, Kind: assetdom.SourceKindScan, Name: "dnsx", Element: "3.11.53.20", FirstSeen: at(0), LastSeen: at(3), RemovedAt: gone(4)},
		{Attribute: ip, Kind: assetdom.SourceKindScan, Name: "migrated_resolves_to", Element: "3.11.53.20", FirstSeen: at(-5), LastSeen: at(2), RemovedAt: gone(7)},
		{Attribute: ip, Kind: assetdom.SourceKindScan, Name: "dnsx", Element: "198.51.100.77", FirstSeen: at(0), LastSeen: at(9)},
		{Attribute: assetdom.SetAttrTechnologies, Kind: assetdom.SourceKindScan, Name: "httpx", Element: "nginx", FirstSeen: at(0), LastSeen: at(9)},
	}
	items, truncated := foldNameAddresses(rows, edgeaddr.Default())
	if truncated != 0 || len(items) != 3 {
		t.Fatalf("items %+v truncated %d", items, truncated)
	}
	// Current first (the dedicated one sorts before the provider's by
	// provider name ""), then the removed CloudFront address.
	if items[0].Address != "198.51.100.77" || items[1].Address != "13.107.128.10" || items[2].Address != "3.11.53.20" {
		t.Fatalf("order %s %s %s", items[0].Address, items[1].Address, items[2].Address)
	}
	m := items[1]
	if !m.Current || m.RemovedAt != nil || !m.FirstSeen.Equal(at(1)) || !m.LastSeen.Equal(at(9)) || m.Provider != "Microsoft 365" || len(m.Sources) != 2 {
		t.Fatalf("Microsoft 365 address %+v", m)
	}
	c := items[2]
	if c.Current || c.RemovedAt == nil || !c.RemovedAt.Equal(at(7)) || !c.FirstSeen.Equal(at(-5)) || c.Provider != "Amazon CloudFront" {
		t.Fatalf("CloudFront address %+v", c)
	}
	if items[0].Provider != "" || items[0].Class != "" {
		t.Fatalf("dedicated address got a provider %+v", items[0])
	}
}
