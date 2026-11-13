package aipolicy

import (
	"fmt"
	"sort"
)

// Class is the data class of a field the platform may put in an AI context
// bundle. A bundle's class is the highest class of any field in it. Design:
// docs/architecture/ai-context-masking.md (data classes).
type Class string

const (
	// ClassPublic is public knowledge: CVE text, CWE, KEV/EPSS, advisories.
	ClassPublic Class = "public"
	// ClassInternal is the organization's own finding and asset facts,
	// redacted and masked.
	ClassInternal Class = "internal"
	// ClassRestricted is raw evidence, code snippets and pentest prose up to
	// the organization's TLP limit.
	ClassRestricted Class = "restricted"
	// ClassTenantOnly never leaves the organization's own infrastructure.
	ClassTenantOnly Class = "tenant_only"
)

var classRank = map[Class]int{ClassPublic: 1, ClassInternal: 2, ClassRestricted: 3, ClassTenantOnly: 4}

// Valid reports a known class.
func (c Class) Valid() bool { return classRank[c] > 0 }

// AtMost reports that c is at or below ceiling. An unknown class is never
// within any ceiling (fail closed).
func (c Class) AtMost(ceiling Class) bool {
	return c.Valid() && ceiling.Valid() && classRank[c] <= classRank[ceiling]
}

// ParseClass parses a class name.
func ParseClass(s string) (Class, error) {
	c := Class(s)
	if !c.Valid() {
		return "", fmt.Errorf("unknown data class %q", s)
	}
	return c, nil
}

// Field is the name of one field the bundle builder can emit.
type Field string

// The finding bundle's fields and their classes.
const (
	FieldFindingTitle        Field = "finding.title"
	FieldFindingDescription  Field = "finding.description"
	FieldFindingSeverity     Field = "finding.severity"
	FieldFindingCVSS         Field = "finding.cvss"
	FieldFindingCVE          Field = "finding.cve"
	FieldFindingCWE          Field = "finding.cwe"
	FieldFindingOWASP        Field = "finding.owasp"
	FieldFindingSource       Field = "finding.source"
	FieldFindingTool         Field = "finding.tool"
	FieldFindingFile         Field = "finding.file"
	FieldFindingSnippet      Field = "finding.snippet"
	FieldFindingExposure     Field = "finding.internet_accessible"
	FieldFindingDataExposure Field = "finding.data_exposure"
	FieldFindingCompliance   Field = "finding.compliance"
	FieldFindingKEV          Field = "finding.kev"
	FieldFindingEPSS         Field = "finding.epss"
	FieldFindingPriority     Field = "finding.priority"
	FieldAssetName           Field = "asset.name"
	FieldAssetType           Field = "asset.type"
	FieldAssetCriticality    Field = "asset.criticality"
	FieldAssetEnvironment    Field = "asset.environment"
	FieldAssetExposure       Field = "asset.exposure"
)

// fieldClasses is the one registry of field classes, shared by the bundle
// builder and every AI caller. A field missing here is tenant-only (never
// sent).
var fieldClasses = map[Field]Class{
	FieldFindingCVE:          ClassPublic,
	FieldFindingCWE:          ClassPublic,
	FieldFindingOWASP:        ClassPublic,
	FieldFindingKEV:          ClassPublic,
	FieldFindingEPSS:         ClassPublic,
	FieldFindingTitle:        ClassInternal,
	FieldFindingDescription:  ClassInternal,
	FieldFindingSeverity:     ClassInternal,
	FieldFindingCVSS:         ClassInternal,
	FieldFindingSource:       ClassInternal,
	FieldFindingTool:         ClassInternal,
	FieldFindingFile:         ClassInternal,
	FieldFindingExposure:     ClassInternal,
	FieldFindingDataExposure: ClassInternal,
	FieldFindingCompliance:   ClassInternal,
	FieldFindingPriority:     ClassInternal,
	FieldAssetName:           ClassInternal,
	FieldAssetType:           ClassInternal,
	FieldAssetCriticality:    ClassInternal,
	FieldAssetEnvironment:    ClassInternal,
	FieldAssetExposure:       ClassInternal,
	FieldFindingSnippet:      ClassRestricted,
}

// ClassOf is a field's class; an unregistered field is tenant-only.
func ClassOf(f Field) Class {
	if c, ok := fieldClasses[f]; ok {
		return c
	}
	return ClassTenantOnly
}

// Allowed reports whether a field may be sent under ceiling.
func Allowed(f Field, ceiling Class) bool { return ClassOf(f).AtMost(ceiling) }

// Classify splits fields into those allowed under ceiling and those
// withheld, and returns the class of the allowed set (the highest class in
// it; public for an empty set). Both lists are sorted.
func Classify(fields []Field, ceiling Class) (allowed, withheld []Field, class Class) {
	class = ClassPublic
	for _, f := range fields {
		if Allowed(f, ceiling) {
			allowed = append(allowed, f)
			if c := ClassOf(f); classRank[c] > classRank[class] {
				class = c
			}
		} else {
			withheld = append(withheld, f)
		}
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i] < allowed[j] })
	sort.Slice(withheld, func(i, j int) bool { return withheld[i] < withheld[j] })
	return allowed, withheld, class
}

// AllowedFields lists every registered field allowed under ceiling, sorted.
func AllowedFields(ceiling Class) []Field {
	out := make([]Field, 0, len(fieldClasses))
	for f := range fieldClasses {
		if Allowed(f, ceiling) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
