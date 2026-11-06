package threat

import (
	"encoding/json"
	"testing"
)

// realKEVShape mirrors the live CISA KEV catalog (and its cisagov GitHub
// mirror): `cwes` is a JSON ARRAY. The struct field was previously typed
// `string`, which unmarshalled fine only while the upstream fetch was failing;
// the moment the fetch was repaired every KEV sync broke with
// "cannot unmarshal array into Go struct field ... cwes of type string".
const realKEVShape = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.07.23",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 RCE",
      "dateAdded": "2021-12-10",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": "",
      "cwes": ["CWE-917", "CWE-502"]
    },
    {
      "cveID": "CVE-2026-0001",
      "vendorProject": "Example",
      "product": "Thing",
      "vulnerabilityName": "Example bug",
      "dateAdded": "2026-01-01",
      "dueDate": "2026-01-15",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "",
      "cwes": ["NVD-CWE-noinfo"]
    }
  ]
}`

func TestKEV_ParsesCwesArray(t *testing.T) {
	var catalog kevCatalogResponse
	if err := json.Unmarshal([]byte(realKEVShape), &catalog); err != nil {
		t.Fatalf("KEV JSON with a cwes array must unmarshal, got: %v", err)
	}

	entries := kevEntriesFromCatalog(catalog)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	// First entry keeps both concrete CWE ids from the array.
	if got := entries[0].CVEID(); got != "CVE-2021-44228" {
		t.Errorf("cve = %q, want CVE-2021-44228", got)
	}
	cwes := entries[0].CWEs()
	if len(cwes) != 2 || cwes[0] != "CWE-917" || cwes[1] != "CWE-502" {
		t.Errorf("cwes = %v, want [CWE-917 CWE-502]", cwes)
	}

	// Second entry's only CWE is the NVD placeholder → dropped, leaving none.
	if got := entries[1].CWEs(); len(got) != 0 {
		t.Errorf("placeholder CWE should be dropped; got %v", got)
	}
}
