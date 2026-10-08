// Package sbomexport writes a software bill of materials from the components
// the platform stores, as CycloneDX 1.6 JSON or SPDX 2.3 JSON.
//
// The encoders are pure: the caller collects the components (tenant- and
// data-scope-filtered) and passes them in. Every document they produce is
// valid against the official JSON schema of its format (the tests validate
// against the vendored schemas in testdata).
package sbomexport

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Format is an SBOM output format.
type Format string

const (
	// FormatCycloneDX is CycloneDX 1.6 JSON.
	FormatCycloneDX Format = "cyclonedx"
	// FormatSPDX is SPDX 2.3 JSON.
	FormatSPDX Format = "spdx"
)

// ParseFormat validates a format name; empty means CycloneDX.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case "", FormatCycloneDX:
		return FormatCycloneDX, nil
	case FormatSPDX:
		return FormatSPDX, nil
	default:
		return "", fmt.Errorf("unsupported SBOM format %q (use cyclonedx or spdx)", s)
	}
}

// ContentType is the media type of a format.
func (f Format) ContentType() string {
	if f == FormatSPDX {
		return "application/spdx+json"
	}
	return "application/vnd.cyclonedx+json; version=1.6"
}

// FileExtension is the conventional file name suffix of a format.
func (f Format) FileExtension() string {
	if f == FormatSPDX {
		return ".spdx.json"
	}
	return ".cdx.json"
}

// Component is one entry of the bill of materials.
type Component struct {
	// ID is the platform's component id; it keeps references unique.
	ID        string
	Name      string
	Version   string
	Ecosystem string
	PURL      string
	// Licenses are the license strings observed for the component.
	Licenses           []string
	VulnerabilityCount int
}

// Document is what an SBOM describes.
type Document struct {
	// Subject names what the components belong to (an asset, or the
	// organization's inventory).
	Subject string
	// SerialUUID makes the document unique (CycloneDX serialNumber, SPDX
	// namespace); a random UUID.
	SerialUUID  string
	Created     time.Time
	ToolVersion string
	Components  []Component
}

// Encode writes doc in the format.
func Encode(f Format, doc Document) ([]byte, error) {
	if f == FormatSPDX {
		return SPDX(doc)
	}
	return CycloneDX(doc)
}

// spdxSchema is the SPDX license list as CycloneDX 1.6 publishes it
// (spdx.schema.json: an enum of license ids). It decides whether a license
// string is an SPDX id (written as an id) or free text (written as a name).
//
//go:embed spdx.schema.json
var spdxSchema []byte

var spdxIDs = func() map[string]string {
	var s struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(spdxSchema, &s); err != nil {
		panic("sbomexport: embedded SPDX license list: " + err.Error())
	}
	m := make(map[string]string, len(s.Enum))
	for _, id := range s.Enum {
		m[strings.ToLower(id)] = id
	}
	return m
}()

// spdxLicenseID returns the canonical SPDX id of a license string, if it is one.
func spdxLicenseID(license string) (string, bool) {
	id, ok := spdxIDs[strings.ToLower(strings.TrimSpace(license))]
	return id, ok
}

// cleanLicenses trims, drops empty and NOASSERTION values, splits the
// comma-joined observations and de-duplicates, keeping the order stable.
func cleanLicenses(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		for _, l := range strings.Split(raw, ",") {
			l = strings.TrimSpace(l)
			if l == "" || strings.EqualFold(l, "NOASSERTION") || strings.EqualFold(l, "NONE") {
				continue
			}
			key := strings.ToLower(l)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// sortedComponents orders components by name, version and id so the same
// inventory always gives the same document body.
func sortedComponents(in []Component) []Component {
	out := append([]Component(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func toolVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "dev"
	}
	return v
}
