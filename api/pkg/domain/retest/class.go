package retest

import "strings"

// Class is what the settlement needs to know about a finding beyond one
// attempt's evidence: whether its check is an exposure class, and whether
// the attempt before it was already an origin refusal.
type Class struct {
	// Exposure: the check reports something the server hands out (an exposed
	// page, panel, document, config or backup file, debug endpoint, listing).
	// A server that now refuses the request has removed what was exposed.
	Exposure bool
	// PriorAccessDenied: the finding's previous completed retest was an
	// inconclusive origin refusal of the same check.
	PriorAccessDenied bool
	// ReachConfirmed: the reachability probe of this retest saw the host
	// answer. Set by Decide, not by the caller.
	ReachConfirmed bool
}

func firstClass(c []Class) Class {
	if len(c) == 0 {
		return Class{}
	}
	return c[0]
}

// exposureTags are check tags (nuclei template tags) of the exposure class.
var exposureTags = map[string]bool{
	"exposure": true, "exposures": true, "exposed": true, "exposed-panel": true, "panel": true,
	"swagger": true, "openapi": true, "api-docs": true, "apidocs": true,
	"config": true, "configs": true, "backup": true, "backups": true, "debug": true,
	"listing": true, "disclosure": true, "logs": true, "git": true,
}

// activeClassTags mark a check that attacks or bypasses something: a refusal
// never proves such a weakness gone. They win over any exposure tag.
var activeClassTags = map[string]bool{
	"rce": true, "sqli": true, "xss": true, "lfi": true, "rfi": true, "ssrf": true, "ssti": true,
	"xxe": true, "injection": true, "traversal": true, "auth-bypass": true, "bypass": true,
	"default-login": true, "takeover": true, "deserialization": true, "cmdi": true, "redirect": true,
	"csrf": true, "idor": true, "intrusive": true, "fuzz": true, "dos": true,
}

// ExposureClass reports whether a check is of the exposure class, from the
// tags recorded with the finding (the template's tags). A check with no tags
// is not: the default is the careful one.
func ExposureClass(tags []string) bool {
	exposure := false
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if activeClassTags[t] {
			return false
		}
		if exposureTags[t] {
			exposure = true
		}
	}
	return exposure
}
