package asset

import "testing"

// The keys the recon converter writes are part of the schema of the asset
// they land on (live warned "outside the asset type schema" for each):
// counts, web fingerprints, the certificate fingerprint (ingest correlates
// certificates by it) and the discovery method as attributes, the
// name-mismatch flag as a synonym of the boolean attribute.
func TestReconPropertyKeysAreKnown(t *testing.T) {
	for _, c := range []struct {
		typ AssetType
		sub string
		key string
	}{
		{AssetTypeIPAddress, "", "open_port_count"},
		{AssetTypeSubdomain, "", "dns_record_count"},
		{AssetTypeDomain, "", "dns_record_count"},
		{AssetTypeSubdomain, "", "discovery_method"},
		{AssetTypeCertificate, "", "fingerprint"},
		{AssetTypeCertificate, "", "host_mismatch"},
		{AssetTypeService, "http", "tls_fingerprint"},
		{AssetTypeService, "http", "cdn_type"},
		{AssetTypeService, "http", "favicon_mmh3"},
	} {
		if u := UnknownPropertyKeys(c.typ, c.sub, map[string]any{c.key: 1}); len(u) != 0 {
			t.Errorf("%s/%s: %q is outside the schema", c.typ, c.sub, c.key)
		}
	}
	if CanonicalPropertyKey("host_mismatch") != "is_host_mismatch" {
		t.Error("host_mismatch does not fold into is_host_mismatch")
	}
}
