package sbomexport

import (
	"encoding/json"
	"strconv"
	"time"
)

type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     cdxTools      `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Licenses   []cdxLicense  `json:"licenses,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxLicense struct {
	License cdxLicenseBody `json:"license"`
}

type cdxLicenseBody struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CycloneDX writes doc as a CycloneDX 1.6 JSON document.
func CycloneDX(doc Document) ([]byte, error) {
	comps := sortedComponents(doc.Components)
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + doc.SerialUUID,
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: doc.Created.UTC().Format(time.RFC3339),
			Tools: cdxTools{Components: []cdxComponent{{
				Type: "application", Name: "OpenCTEM", Version: toolVersion(doc.ToolVersion),
			}}},
		},
		Components: make([]cdxComponent, 0, len(comps)),
	}
	if doc.Subject != "" {
		bom.Metadata.Component = &cdxComponent{Type: "application", BOMRef: "subject", Name: doc.Subject}
	}
	for _, c := range comps {
		cc := cdxComponent{
			Type:    "library",
			BOMRef:  "component-" + c.ID,
			Name:    c.Name,
			Version: c.Version,
			PURL:    c.PURL,
		}
		for _, l := range cleanLicenses(c.Licenses) {
			if id, ok := spdxLicenseID(l); ok {
				cc.Licenses = append(cc.Licenses, cdxLicense{License: cdxLicenseBody{ID: id}})
			} else {
				cc.Licenses = append(cc.Licenses, cdxLicense{License: cdxLicenseBody{Name: l}})
			}
		}
		if c.Ecosystem != "" {
			cc.Properties = append(cc.Properties, cdxProperty{Name: "openctem:ecosystem", Value: c.Ecosystem})
		}
		cc.Properties = append(cc.Properties, cdxProperty{
			Name: "openctem:vulnerability_count", Value: strconv.Itoa(c.VulnerabilityCount),
		})
		bom.Components = append(bom.Components, cc)
	}
	return json.MarshalIndent(bom, "", "  ")
}
