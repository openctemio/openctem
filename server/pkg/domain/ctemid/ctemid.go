// Package ctemid maps OpenCTEM exposures to CTEM-ID codes, the exposure
// identifiers published at https://ctem.org. Our exposure taxonomy stays the
// primary one; the code is an interoperability label derived at read time
// from data we already hold (docs/architecture/ctem-id-mapping.md).
//
// Only the codes are held here: no titles or descriptions from the catalog.
// A CTEM-ID names an exposure class together with who owns or relates to the
// exposed thing (the organization, a vendor, an employee, a customer) and
// sometimes how it was found. Our event types carry the class only, so a code
// is chosen from the event type, its details and the linked asset. When those
// do not settle the code there is no code: Map never guesses.
package ctemid

import "strings"

// CatalogVersion is the version of the CTEM-ID catalog the codes and rules
// below follow. A change of rules or codes bumps it; nothing is stored, so a
// new rule applies to every exposure on its next read.
const CatalogVersion = "1.0"

// Code is a CTEM-ID code, such as CTEM-DOM-2.
type Code string

// Every code of catalog version 1.0.
const (
	CodeBND1 Code = "CTEM-BND-1"
	CodeCRD1 Code = "CTEM-CRD-1"
	CodeCRD2 Code = "CTEM-CRD-2"
	CodeDOM1 Code = "CTEM-DOM-1"
	CodeDOM2 Code = "CTEM-DOM-2"
	CodeDOM3 Code = "CTEM-DOM-3"
	CodeDOM4 Code = "CTEM-DOM-4"
	CodeEXP1 Code = "CTEM-EXP-1"
	CodeEXP2 Code = "CTEM-EXP-2"
	CodeEXP3 Code = "CTEM-EXP-3"
	CodeEXP4 Code = "CTEM-EXP-4"
	CodeEXP5 Code = "CTEM-EXP-5"
	CodeEXP6 Code = "CTEM-EXP-6"
	CodeFIN1 Code = "CTEM-FIN-1"
	CodeFIN2 Code = "CTEM-FIN-2"
	CodeINF1 Code = "CTEM-INF-1"
	CodeINF2 Code = "CTEM-INF-2"
	CodeINF3 Code = "CTEM-INF-3"
	CodeINF4 Code = "CTEM-INF-4"
	CodeINF5 Code = "CTEM-INF-5"
	CodeINF6 Code = "CTEM-INF-6"
	CodeINF7 Code = "CTEM-INF-7"
	CodeRAN1 Code = "CTEM-RAN-1"
	CodeRAN2 Code = "CTEM-RAN-2"
	CodeSRC1 Code = "CTEM-SRC-1"
	CodeSRC2 Code = "CTEM-SRC-2"
	CodeSRC3 Code = "CTEM-SRC-3"
	CodeSRC4 Code = "CTEM-SRC-4"
	CodeSRC5 Code = "CTEM-SRC-5"
)

// Codes returns every code of the catalog version, in catalog order.
func Codes() []Code {
	return []Code{
		CodeBND1, CodeCRD1, CodeCRD2, CodeDOM1, CodeDOM2, CodeDOM3, CodeDOM4,
		CodeEXP1, CodeEXP2, CodeEXP3, CodeEXP4, CodeEXP5, CodeEXP6, CodeFIN1, CodeFIN2,
		CodeINF1, CodeINF2, CodeINF3, CodeINF4, CodeINF5, CodeINF6, CodeINF7,
		CodeRAN1, CodeRAN2, CodeSRC1, CodeSRC2, CodeSRC3, CodeSRC4, CodeSRC5,
	}
}

// Known reports whether c is a code of the catalog version.
func (c Code) Known() bool {
	for _, k := range Codes() {
		if k == c {
			return true
		}
	}
	return false
}

// URL is the code's page on ctem.org, or "" for an unknown code.
func (c Code) URL() string {
	if !c.Known() {
		return ""
	}
	return "https://ctem.org/docs/" + strings.ToLower(string(c))
}
