package vulnbundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func vulnIDsGz(t *testing.T, lines ...string) ([]byte, *VulnIDsManifest) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	for _, l := range lines {
		_, _ = zw.Write([]byte(l + "\n"))
	}
	_ = zw.Close()
	gz := buf.Bytes()
	sum := sha256.Sum256(gz)
	return gz, &VulnIDsManifest{Files: []File{{Name: VulnIDsEntriesFile, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(gz)), Records: len(lines)}}}
}

func TestParseVulnIDEntries(t *testing.T) {
	gz, m := vulnIDsGz(t,
		`{"id":"GHSA-35jh-r3h4-6jhm","cve":"CVE-2021-23337","source":"ghsa"}`,
		`{"id":"PYSEC-2021-19","cve":"CVE-2021-0001","source":"osv"}`,
		`{"id":"PYSEC-2021-19","cve":"CVE-2021-0002","source":"osv"}`,
		`{"id":"RHSA-2023:4520","cve":"CVE-2023-32681","source":"osv"}`,
		`{"id":"GHSA-2222-3333-4444","cve":"CVE-2022-1111","source":"ghsa"}`,
		`{"id":"GHSA-2222-3333-4444","cve":"CVE-2022-1111","source":"ghsa"}`)
	res, err := ParseVulnIDEntries(gz, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 2 || res.Conflicting != 1 || res.Invalid != 1 {
		t.Fatalf("entries %+v conflicting %d invalid %d", res.Entries, res.Conflicting, res.Invalid)
	}
	for _, e := range res.Entries {
		if e.ID == "PYSEC-2021-19" {
			t.Fatal("an id listed with two CVEs was kept")
		}
	}
}

func TestParseVulnIDEntries_RefusesTamperingAndCounts(t *testing.T) {
	gz, m := vulnIDsGz(t, `{"id":"GHSA-35jh-r3h4-6jhm","cve":"CVE-2021-23337","source":"ghsa"}`)
	bad := append([]byte{}, gz...)
	bad[len(bad)-1] ^= 0xff
	if _, err := ParseVulnIDEntries(bad, m); err == nil {
		t.Fatal("a tampered file was accepted")
	}
	m.Files[0].Records = 2
	if _, err := ParseVulnIDEntries(gz, m); err == nil {
		t.Fatal("a record count mismatch was accepted")
	}
	gz2, m2 := vulnIDsGz(t, `{"id":"GHSA-35jh-r3h4-6jhm","cve":"CVE-2021-23337","source":"ghsa","extra":1}`)
	if _, err := ParseVulnIDEntries(gz2, m2); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}
