// Package betterleaks provides an adapter to convert Betterleaks (v1) JSON
// reports to CTIS. gitleaks reports have the same format and convert too.
package betterleaks

// Finding represents a single finding of a betterleaks/gitleaks JSON report.
type Finding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match,omitempty"`
	Secret      string   `json:"Secret,omitempty"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile,omitempty"`
	Commit      string   `json:"Commit,omitempty"`
	Entropy     float64  `json:"Entropy,omitempty"`
	Author      string   `json:"Author,omitempty"`
	Email       string   `json:"Email,omitempty"`
	Date        string   `json:"Date,omitempty"`
	Message     string   `json:"Message,omitempty"`
	Tags        []string `json:"Tags,omitempty"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint,omitempty"`
}
