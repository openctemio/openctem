package stage

import "strings"

// webStages are the stages whose tools request web paths: a job of theirs
// keeps to the tenant's path exclusions through its web scope
// (docs/rfcs/RFC-056-web-attack-surface.md §5, RFC-055 §6.1).
var webStages = map[Key]bool{CrawlWeb: true, VulnTemplates: true, DASTWeb: true}

// IsWebStage reports whether a stage's tools request web paths.
func IsWebStage(k Key) bool { return webStages[k] }

// WebTool reports whether a tool implements a web stage. It is decided by
// the tool alone, so a web tool in a step outside the stage catalog (a
// quick scan, a step without a stage) is still one.
func (c Catalog) WebTool(tool string) bool {
	for _, s := range c.ForTool(tool) {
		if webStages[s.Key] {
			return true
		}
	}
	return false
}

// WebCapability reports whether a capability word names a web stage: a
// stage key, its versioned id ("vuln.templates@1") or a pre-catalog word
// that names one stage ("crawler").
func WebCapability(word string) bool {
	word, _, _ = strings.Cut(strings.TrimSpace(word), "@")
	s, ok := ForWord(word)
	return ok && webStages[s.Key]
}
