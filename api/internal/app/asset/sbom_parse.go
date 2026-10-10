package asset

// SBOM parsing (CycloneDX 1.4-1.6 JSON, SPDX 2.2/2.3 JSON) into package
// nodes with their dependency graph. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

// SBOM formats.
const (
	SBOMFormatCycloneDX = "cyclonedx"
	SBOMFormatSPDX      = "spdx"
)

// maxSBOMIssues caps the issues a preview reports.
const maxSBOMIssues = 100

// maxCycloneDXNesting bounds nested components (a hostile document can nest
// without end).
const maxCycloneDXNesting = 16

// SBOMIssue is an entry the importer skipped and why.
type SBOMIssue struct {
	Ref    string `json:"ref"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}

// ParsedSBOM is the package graph of one SBOM document.
type ParsedSBOM struct {
	Format      string
	SpecVersion string
	Nodes       []software.PackageNode
	Total       int
	Issues      []SBOMIssue
	Skipped     int
	Edges       int
}

func (p *ParsedSBOM) issue(ref, name, reason string) {
	p.Skipped++
	if len(p.Issues) < maxSBOMIssues {
		p.Issues = append(p.Issues, SBOMIssue{Ref: clipText(ref, 256), Name: clipText(name, 256), Reason: reason})
	}
}

func clipText(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ParseSBOM detects the format and parses the document.
func ParseSBOM(data []byte) (*ParsedSBOM, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("%w: the file is not valid JSON", shared.ErrValidation)
	}
	switch {
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return parseCycloneDX(data)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2."):
		return parseSPDX(data)
	case probe.SPDXVersion != "":
		return nil, fmt.Errorf("%w: SPDX version %q is not supported (SPDX 2.2 or 2.3 JSON)", shared.ErrValidation, clipText(probe.SPDXVersion, 32))
	default:
		return nil, fmt.Errorf("%w: unrecognized SBOM format (expected CycloneDX or SPDX JSON)", shared.ErrValidation)
	}
}

type cdxLicense struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license,omitempty"`
	Expression string `json:"expression,omitempty"`
}

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	Type       string         `json:"type"`
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Scope      string         `json:"scope"`
	Licenses   []cdxLicense   `json:"licenses"`
	Components []cdxComponent `json:"components"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Evidence *struct {
		Occurrences []struct {
			Location string `json:"location"`
		} `json:"occurrences"`
	} `json:"evidence"`
}

type cdxDocument struct {
	SpecVersion string `json:"specVersion"`
	Metadata    *struct {
		Component *cdxComponent `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func cdxLicenses(ls []cdxLicense) []string {
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		switch {
		case l.Expression != "":
			out = append(out, l.Expression)
		case l.License != nil && l.License.ID != "":
			out = append(out, l.License.ID)
		case l.License != nil && l.License.Name != "":
			out = append(out, l.License.Name)
		}
	}
	return software.NormalizeLicenses(out)
}

func cdxLocation(c *cdxComponent) string {
	if c.Evidence != nil {
		for _, o := range c.Evidence.Occurrences {
			if o.Location != "" {
				return o.Location
			}
		}
	}
	for _, p := range c.Properties {
		if strings.HasSuffix(p.Name, ":location:0:path") || p.Name == "aquasecurity:trivy:FilePath" {
			return p.Value
		}
	}
	return ""
}

func parseCycloneDX(data []byte) (*ParsedSBOM, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: the CycloneDX document does not parse", shared.ErrValidation)
	}
	out := &ParsedSBOM{Format: SBOMFormatCycloneDX, SpecVersion: clipText(doc.SpecVersion, 16)}
	rootRef := ""
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		rootRef = doc.Metadata.Component.BOMRef
	}
	deps := map[string][]string{}
	edges := 0
	for _, d := range doc.Dependencies {
		edges += len(d.DependsOn)
		if edges > software.MaxSnapshotEdges {
			return nil, fmt.Errorf("%w: at most %d dependency edges per SBOM", shared.ErrValidation, software.MaxSnapshotEdges)
		}
		deps[d.Ref] = append(deps[d.Ref], d.DependsOn...)
	}
	direct := map[string]bool{}
	for _, ref := range deps[rootRef] {
		direct[ref] = true
	}
	var walk func(cs []cdxComponent, level int) error
	walk = func(cs []cdxComponent, level int) error {
		if level > maxCycloneDXNesting {
			return fmt.Errorf("%w: components are nested too deeply", shared.ErrValidation)
		}
		for i := range cs {
			c := &cs[i]
			out.Total++
			if out.Total > software.MaxSnapshotPackages {
				return fmt.Errorf("%w: at most %d components per SBOM", shared.ErrValidation, software.MaxSnapshotPackages)
			}
			if err := walk(c.Components, level+1); err != nil {
				return err
			}
			switch strings.ToLower(c.Type) {
			case "", "library", "framework", "application", "container", "operating-system", "platform", "firmware", "device-driver":
			default:
				continue // files, data, services, ML models: not packages
			}
			ref := c.BOMRef
			if ref == "" {
				ref = c.PURL
			}
			name := c.Name
			if c.Group != "" {
				name = c.Group + "/" + c.Name
			}
			n := software.PackageNode{Ref: ref, DisplayName: clipText(name, software.MaxNameLen)}
			p, err := software.ParsePURL(c.PURL)
			if err != nil {
				if c.PURL != "" {
					out.issue(ref, name, "invalid package URL")
					continue
				}
				p, err = software.SyntheticPURL("", name, c.Version)
				if err != nil {
					out.issue(ref, name, "no package URL and no usable name")
					continue
				}
				n.Synthetic = true
			}
			if p.Version == "" {
				p.Version = clipVersion(c.Version)
			}
			n.PURL = p
			n.Scope = software.NormalizeScope(c.Scope)
			n.Licenses = cdxLicenses(c.Licenses)
			n.Location = software.CleanLocation(cdxLocation(c))
			n.DependsOn = deps[c.BOMRef]
			n.Relationship = software.RelationshipUnknown
			if direct[c.BOMRef] {
				n.Relationship = software.RelationshipDirect
			}
			out.Nodes = append(out.Nodes, n)
		}
		return nil
	}
	if err := walk(doc.Components, 0); err != nil {
		return nil, err
	}
	planned, _ := software.PlanGraph(out.Nodes)
	out.Edges = len(planned)
	return out, nil
}

func clipVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > software.MaxPackageVer {
		v = v[:software.MaxPackageVer]
	}
	return v
}

type spdxDocumentJSON struct {
	SPDXVersion       string   `json:"spdxVersion"`
	DocumentDescribes []string `json:"documentDescribes"`
	Packages          []struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		LicenseConcluded string `json:"licenseConcluded"`
		LicenseDeclared  string `json:"licenseDeclared"`
		ExternalRefs     []struct {
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceType     string `json:"referenceType"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Relationships []struct {
		From string `json:"spdxElementId"`
		Type string `json:"relationshipType"`
		To   string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

// spdxScopes are the SPDX "X_DEPENDENCY_OF" relationships and their scope.
var spdxScopes = map[string]string{
	"DEV_DEPENDENCY_OF":      software.ScopeDevelopment,
	"TEST_DEPENDENCY_OF":     software.ScopeTest,
	"OPTIONAL_DEPENDENCY_OF": software.ScopeOptional,
	"BUILD_DEPENDENCY_OF":    software.ScopeBuild,
	"PROVIDED_DEPENDENCY_OF": software.ScopeProvided,
	"RUNTIME_DEPENDENCY_OF":  software.ScopeRuntime,
	"DEPENDENCY_OF":          "",
}

//nolint:cyclop // one pass per SPDX section
func parseSPDX(data []byte) (*ParsedSBOM, error) {
	var doc spdxDocumentJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: the SPDX document does not parse", shared.ErrValidation)
	}
	if len(doc.Packages) > software.MaxSnapshotPackages {
		return nil, fmt.Errorf("%w: at most %d packages per SBOM", shared.ErrValidation, software.MaxSnapshotPackages)
	}
	if len(doc.Relationships) > software.MaxSnapshotEdges {
		return nil, fmt.Errorf("%w: at most %d relationships per SBOM", shared.ErrValidation, software.MaxSnapshotEdges)
	}
	out := &ParsedSBOM{Format: SBOMFormatSPDX, SpecVersion: clipText(strings.TrimPrefix(doc.SPDXVersion, "SPDX-"), 16)}
	roots := map[string]bool{}
	for _, r := range doc.DocumentDescribes {
		roots[r] = true
	}
	children := map[string][]string{}
	scopes := map[string]string{}
	for _, r := range doc.Relationships {
		t := strings.ToUpper(r.Type)
		switch {
		case t == "DESCRIBES" && strings.HasPrefix(r.From, "SPDXRef-DOCUMENT"):
			roots[r.To] = true
		case t == "DEPENDS_ON":
			children[r.From] = append(children[r.From], r.To)
		default:
			if scope, ok := spdxScopes[t]; ok {
				children[r.To] = append(children[r.To], r.From)
				if scope != "" {
					scopes[r.From] = scope
				}
			}
		}
	}
	direct := map[string]bool{}
	for root := range roots {
		for _, c := range children[root] {
			direct[c] = true
		}
	}
	for _, pkg := range doc.Packages {
		out.Total++
		if roots[pkg.SPDXID] {
			continue // the described product itself
		}
		purlText := ""
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purlText = ref.ReferenceLocator
				break
			}
		}
		n := software.PackageNode{Ref: pkg.SPDXID, DisplayName: clipText(pkg.Name, software.MaxNameLen)}
		p, err := software.ParsePURL(purlText)
		if err != nil {
			if purlText != "" {
				out.issue(pkg.SPDXID, pkg.Name, "invalid package URL")
				continue
			}
			p, err = software.SyntheticPURL("", pkg.Name, pkg.VersionInfo)
			if err != nil {
				out.issue(pkg.SPDXID, pkg.Name, "no package URL and no usable name")
				continue
			}
			n.Synthetic = true
		}
		if p.Version == "" {
			p.Version = clipVersion(pkg.VersionInfo)
		}
		n.PURL = p
		lic := pkg.LicenseConcluded
		if lic == "" || strings.EqualFold(lic, "NOASSERTION") {
			lic = pkg.LicenseDeclared
		}
		n.Licenses = software.NormalizeLicenses([]string{lic})
		n.Scope = scopes[pkg.SPDXID]
		n.DependsOn = children[pkg.SPDXID]
		n.Relationship = software.RelationshipUnknown
		if direct[pkg.SPDXID] {
			n.Relationship = software.RelationshipDirect
		}
		out.Nodes = append(out.Nodes, n)
	}
	planned, _ := software.PlanGraph(out.Nodes)
	out.Edges = len(planned)
	return out, nil
}
