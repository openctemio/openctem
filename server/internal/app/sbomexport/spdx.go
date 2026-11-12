package sbomexport

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const noAssertion = "NOASSERTION"

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	LicenseComments  string            `json:"licenseComments,omitempty"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// spdxIDUnsafe matches what an SPDX element id may not contain
// (SPDXRef-[a-zA-Z0-9.-]+).
var spdxIDUnsafe = regexp.MustCompile(`[^a-zA-Z0-9.-]`)

// SPDX writes doc as an SPDX 2.3 JSON document. The document DESCRIBES each
// package. A package declares its license only when exactly one SPDX license
// id was observed; otherwise NOASSERTION, with the observed strings in
// licenseComments.
func SPDX(doc Document) ([]byte, error) {
	comps := sortedComponents(doc.Components)
	name := doc.Subject
	if name == "" {
		name = "OpenCTEM SBOM"
	}
	out := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "urn:uuid:" + doc.SerialUUID,
		CreationInfo: spdxCreationInfo{
			Created:  doc.Created.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: OpenCTEM-" + toolVersion(doc.ToolVersion)},
		},
		Packages:      make([]spdxPackage, 0, len(comps)),
		Relationships: make([]spdxRelationship, 0, len(comps)),
	}
	for _, c := range comps {
		id := "SPDXRef-Package-" + spdxIDUnsafe.ReplaceAllString(c.ID, "-")
		p := spdxPackage{
			SPDXID:           id,
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: noAssertion,
			LicenseConcluded: noAssertion,
			LicenseDeclared:  noAssertion,
			CopyrightText:    noAssertion,
		}
		if lics := cleanLicenses(c.Licenses); len(lics) > 0 {
			if canon, ok := spdxLicenseID(lics[0]); ok && len(lics) == 1 {
				p.LicenseDeclared = canon
			} else {
				p.LicenseComments = "Licenses observed: " + strings.Join(lics, ", ")
			}
		}
		if c.PURL != "" {
			p.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: c.PURL,
			}}
		}
		out.Packages = append(out.Packages, p)
		out.Relationships = append(out.Relationships, spdxRelationship{
			SPDXElementID: "SPDXRef-DOCUMENT", RelatedSPDXElement: id, RelationshipType: "DESCRIBES",
		})
	}
	return json.MarshalIndent(out, "", "  ")
}
