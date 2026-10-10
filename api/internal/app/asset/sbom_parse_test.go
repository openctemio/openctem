package asset

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

const cdxSample = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "shop"}},
  "components": [
    {"bom-ref": "express", "type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2",
     "licenses": [{"license": {"id": "MIT"}}], "evidence": {"occurrences": [{"location": "web/package-lock.json"}]}},
    {"bom-ref": "debug", "type": "library", "name": "debug", "version": "2.6.9", "purl": "pkg:npm/debug@2.6.9", "scope": "excluded",
     "licenses": [{"expression": "MIT OR Apache-2.0"}],
     "components": [{"bom-ref": "ms", "name": "ms", "version": "2.0.0", "purl": "pkg:npm/ms@2.0.0"}]},
    {"bom-ref": "bad", "name": "bad", "purl": "pkg:/nope"},
    {"bom-ref": "file1", "type": "file", "name": "README"},
    {"bom-ref": "noname", "type": "library", "name": " "}
  ],
  "dependencies": [
    {"ref": "app", "dependsOn": ["express"]},
    {"ref": "express", "dependsOn": ["debug"]},
    {"ref": "debug", "dependsOn": ["ms"]}
  ]
}`

func TestParseSBOM_CycloneDX(t *testing.T) {
	p, err := ParseSBOM([]byte(cdxSample))
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != SBOMFormatCycloneDX || p.SpecVersion != "1.6" || p.Total != 6 {
		t.Fatalf("parsed = %+v", p)
	}
	if len(p.Nodes) != 3 || p.Skipped != 2 || len(p.Issues) != 2 || p.Edges != 2 {
		t.Fatalf("nodes=%d skipped=%d issues=%v edges=%d", len(p.Nodes), p.Skipped, p.Issues, p.Edges)
	}
	by := map[string]software.PackageNode{}
	for _, n := range p.Nodes {
		by[n.PURL.Name] = n
	}
	if e := by["express"]; e.Relationship != software.RelationshipDirect || e.Location != "web/package-lock.json" || e.Licenses[0] != "MIT" {
		t.Errorf("express = %+v", e)
	}
	if d := by["debug"]; d.Relationship != software.RelationshipTransitive || d.Scope != software.ScopeDevelopment || d.Licenses[0] != "MIT OR Apache-2.0" {
		t.Errorf("debug = %+v", d)
	}
	if m := by["ms"]; m.Relationship != software.RelationshipTransitive {
		t.Errorf("nested ms = %+v", m)
	}
}

const spdxSample = `{
  "spdxVersion": "SPDX-2.3",
  "documentDescribes": ["SPDXRef-root"],
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "shop"},
    {"SPDXID": "SPDXRef-flask", "name": "Flask", "versionInfo": "3.0.0", "licenseConcluded": "BSD-3-Clause",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/flask@3.0.0"}]},
    {"SPDXID": "SPDXRef-pytest", "name": "pytest", "versionInfo": "8.0.0", "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT"},
    {"SPDXID": "SPDXRef-werk", "name": "werkzeug", "versionInfo": "3.0.1",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/werkzeug@3.0.1"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"},
    {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-flask"},
    {"spdxElementId": "SPDXRef-pytest", "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-root"},
    {"spdxElementId": "SPDXRef-werk", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-flask"}
  ]
}`

func TestParseSBOM_SPDX(t *testing.T) {
	p, err := ParseSBOM([]byte(spdxSample))
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != SBOMFormatSPDX || p.SpecVersion != "2.3" || len(p.Nodes) != 3 {
		t.Fatalf("parsed = %+v", p)
	}
	by := map[string]software.PackageNode{}
	for _, n := range p.Nodes {
		by[n.PURL.Name] = n
	}
	if f := by["flask"]; f.Relationship != software.RelationshipDirect || f.Licenses[0] != "BSD-3-Clause" {
		t.Errorf("flask = %+v", f)
	}
	if py := by["pytest"]; py.Relationship != software.RelationshipDirect || py.Scope != software.ScopeDevelopment || !py.Synthetic || py.Licenses[0] != "MIT" {
		t.Errorf("pytest = %+v", py)
	}
	if w := by["werkzeug"]; w.Relationship != software.RelationshipTransitive {
		t.Errorf("werkzeug = %+v", w)
	}
}

func TestParseSBOM_Refusals(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":     `{"bomFormat":`,
		"unknown":      `{"hello": "world"}`,
		"spdx 3":       `{"spdxVersion": "SPDX-3.0"}`,
		"bad cdx type": `{"bomFormat": "CycloneDX", "components": "nope"}`,
	} {
		if _, err := ParseSBOM([]byte(doc)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
	// Too deep nesting is refused, not recursed without end.
	deep := strings.Repeat(`{"name":"x","version":"1","components":[`, maxCycloneDXNesting+3) + `{"name":"y"}` + strings.Repeat(`]}`, maxCycloneDXNesting+3)
	if _, err := ParseSBOM([]byte(`{"bomFormat":"CycloneDX","components":[` + deep + `]}`)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("deep nesting: %v", err)
	}
}

func TestParseSBOM_ComponentCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"spdxVersion":"SPDX-2.3","packages":[`)
	for i := 0; i <= software.MaxSnapshotPackages; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"SPDXID":"p%d","name":"p%d"}`, i, i)
	}
	b.WriteString(`]}`)
	if _, err := ParseSBOM([]byte(b.String())); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over the package cap: %v", err)
	}
}

func FuzzParseSBOM(f *testing.F) {
	f.Add([]byte(cdxSample))
	f.Add([]byte(spdxSample))
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/%zz"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseSBOM(data)
		if err != nil {
			return
		}
		if len(p.Nodes) > software.MaxSnapshotPackages || len(p.Issues) > maxSBOMIssues {
			t.Fatalf("limits exceeded: %d nodes, %d issues", len(p.Nodes), len(p.Issues))
		}
		for _, n := range p.Nodes {
			if n.PURL.Name == "" || len(n.PURL.Version) > software.MaxPackageVer || len(n.Location) > software.MaxPackageLocation {
				t.Fatalf("invalid node %+v", n)
			}
		}
	})
}
