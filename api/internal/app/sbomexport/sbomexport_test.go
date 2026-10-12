package sbomexport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The official schemas, vendored unchanged: CycloneDX 1.6 (with the SPDX
// license list and JSF schemas it references) and SPDX 2.3.
const (
	cdxSchemaID  = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	spdxSchemaID = "http://spdx.org/rdf/terms/2.3"
)

func compileSchema(t *testing.T, id string, files map[string]string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for url, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if err := c.AddResource(url, doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatalf("compile %s: %v", id, err)
	}
	return s
}

func cycloneDXSchema(t *testing.T) *jsonschema.Schema {
	return compileSchema(t, cdxSchemaID, map[string]string{
		cdxSchemaID: filepath.Join("testdata", "bom-1.6.schema.json"),
		"http://cyclonedx.org/schema/spdx.schema.json":     "spdx.schema.json",
		"http://cyclonedx.org/schema/jsf-0.82.schema.json": filepath.Join("testdata", "jsf-0.82.schema.json"),
	})
}

func spdxDocSchema(t *testing.T) *jsonschema.Schema {
	return compileSchema(t, spdxSchemaID, map[string]string{
		spdxSchemaID: filepath.Join("testdata", "spdx-2.3.schema.json"),
	})
}

func validate(t *testing.T, s *jsonschema.Schema, out []byte) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("output is not valid against the official schema: %v\n%s", err, out)
	}
}

func sampleDoc() Document {
	return Document{
		Subject:     "payments-api",
		SerialUUID:  "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Created:     time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC),
		ToolVersion: "v0.9.0",
		Components: []Component{
			{ID: "0192a1b2-0000-7000-8000-000000000002", Name: "lodash", Version: "4.17.20", Ecosystem: "npm",
				PURL: "pkg:npm/lodash@4.17.20", Licenses: []string{"mit"}, VulnerabilityCount: 2},
			{ID: "0192a1b2-0000-7000-8000-000000000001", Name: "@types/node", Version: "20.1.0", Ecosystem: "npm",
				PURL: "pkg:npm/%40types/node@20.1.0", Licenses: []string{"MIT, Apache-2.0"}},
			// Free-text licenses, a NOASSERTION value and characters that
			// need escaping still give a valid document.
			{ID: "0192a1b2-0000-7000-8000-000000000003", Name: `odd "name" <&>`, Version: "",
				Licenses: []string{"Custom proprietary license", "NOASSERTION", ""}},
		},
	}
}

func TestCycloneDX_ValidAgainstOfficialSchema(t *testing.T) {
	s := cycloneDXSchema(t)
	out, err := CycloneDX(sampleDoc())
	if err != nil {
		t.Fatal(err)
	}
	validate(t, s, out)

	// An empty inventory is a valid (empty) bill of materials too.
	empty, err := CycloneDX(Document{SerialUUID: "3f2504e0-4f89-41d3-9a0c-0305e82c3302", Created: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	validate(t, s, empty)
}

func TestCycloneDX_Content(t *testing.T) {
	out, err := CycloneDX(sampleDoc())
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Components   []struct {
			Name     string `json:"name"`
			PURL     string `json:"purl"`
			Licenses []struct {
				License struct{ ID, Name string } `json:"license"`
			} `json:"licenses"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" ||
		bom.SerialNumber != "urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301" {
		t.Fatalf("header %+v", bom)
	}
	if len(bom.Components) != 3 || bom.Components[0].Name != "@types/node" || bom.Components[1].Name != "lodash" {
		t.Fatalf("components not sorted by name: %+v", bom.Components)
	}
	lodash := bom.Components[1]
	if lodash.PURL != "pkg:npm/lodash@4.17.20" || len(lodash.Licenses) != 1 || lodash.Licenses[0].License.ID != "MIT" {
		t.Fatalf("lodash: purl/license not carried over as an SPDX id: %+v", lodash)
	}
	if got := bom.Components[0].Licenses; len(got) != 2 {
		t.Fatalf("comma-joined licenses not split: %+v", got)
	}
	odd := bom.Components[2]
	if len(odd.Licenses) != 1 || odd.Licenses[0].License.Name != "Custom proprietary license" {
		t.Fatalf("free-text license must be a name, NOASSERTION dropped: %+v", odd.Licenses)
	}
	found := false
	for _, p := range lodash.Properties {
		if p.Name == "openctem:vulnerability_count" && p.Value == "2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("vulnerability count property missing: %+v", lodash.Properties)
	}
}

func TestSPDX_ValidAgainstOfficialSchema(t *testing.T) {
	s := spdxDocSchema(t)
	out, err := SPDX(sampleDoc())
	if err != nil {
		t.Fatal(err)
	}
	validate(t, s, out)

	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			SPDXID          string `json:"SPDXID"`
			Name            string `json:"name"`
			LicenseDeclared string `json:"licenseDeclared"`
			ExternalRefs    []struct {
				ReferenceType, ReferenceLocator string
			} `json:"externalRefs"`
		} `json:"packages"`
		Relationships []struct {
			RelationshipType string `json:"relationshipType"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || len(doc.Packages) != 3 || len(doc.Relationships) != 3 {
		t.Fatalf("document %+v", doc)
	}
	lodash := doc.Packages[1]
	if lodash.LicenseDeclared != "MIT" || len(lodash.ExternalRefs) != 1 || lodash.ExternalRefs[0].ReferenceLocator != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("lodash package %+v", lodash)
	}
	if doc.Packages[0].LicenseDeclared != noAssertion {
		t.Fatalf("two observed licenses must not be declared as one: %q", doc.Packages[0].LicenseDeclared)
	}
	for _, p := range doc.Packages {
		if !strings.HasPrefix(p.SPDXID, "SPDXRef-Package-") || spdxIDUnsafe.MatchString(strings.TrimPrefix(p.SPDXID, "SPDXRef-")) {
			t.Fatalf("bad SPDX id %q", p.SPDXID)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": FormatCycloneDX, "CycloneDX": FormatCycloneDX, "spdx": FormatSPDX} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("an unknown format must be refused")
	}
}

// The validators really check: what the console used to download (a
// CycloneDX-looking object with a non-standard field and no serial number
// pattern) and an SPDX document without its required fields are refused.
func TestSchemas_RejectInvalidDocuments(t *testing.T) {
	bad := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"not-a-urn","version":1,
		"components":[{"type":"library","name":"x","vulnerabilityCount":3}]}`)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	if cycloneDXSchema(t).Validate(inst) == nil {
		t.Fatal("an invalid CycloneDX document passed the schema")
	}
	inst, err = jsonschema.UnmarshalJSON(strings.NewReader(`{"spdxVersion":"SPDX-2.3","packages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if spdxDocSchema(t).Validate(inst) == nil {
		t.Fatal("an invalid SPDX document passed the schema")
	}
}
