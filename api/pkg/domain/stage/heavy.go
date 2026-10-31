package stage

import "time"

// Heavy stages cost the most per target (template scans, crawls,
// screenshots, service detection). In a workflow with delta gating they
// take only the assets that are new, changed or due since the previous run
// of the same scan (docs/architecture/scan-stages.md §1.5).
var heavyMaxAge = map[Key]time.Duration{
	VulnTemplates:             7 * 24 * time.Hour,
	CrawlWeb:                  7 * 24 * time.Hour,
	Key("capture.screenshot"): 7 * 24 * time.Hour,
	Key("detect.services"):    7 * 24 * time.Hour,
}

// Heavy reports whether the stage is gated by delta gating.
func Heavy(k Key) bool {
	_, ok := heavyMaxAge[k]
	return ok
}

// HeavyMaxAge is how long a heavy stage's result counts as done: an asset
// last handled longer ago is due again (0 for a stage that is not heavy).
func HeavyMaxAge(k Key) time.Duration { return heavyMaxAge[k] }
