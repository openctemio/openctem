// Package semgrep provides an adapter to convert Semgrep JSON output to CTIS.
package semgrep

// SemgrepOutput is the root Semgrep JSON document.
type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
	Errors  []SemgrepError  `json:"errors,omitempty"`
	Version string          `json:"version,omitempty"`
}

// SemgrepResult represents a single Semgrep finding.
type SemgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   SemgrepPos   `json:"start"`
	End     SemgrepPos   `json:"end"`
	Extra   SemgrepExtra `json:"extra"`
}

// SemgrepPos represents a position in a file.
type SemgrepPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset,omitempty"`
}

// SemgrepExtra contains additional result information.
type SemgrepExtra struct {
	Message     string           `json:"message"`
	Severity    string           `json:"severity"`
	Metadata    SemgrepMetadata  `json:"metadata,omitempty"`
	Lines       string           `json:"lines,omitempty"`
	IsIgnored   bool             `json:"is_ignored,omitempty"`
	Fingerprint string           `json:"fingerprint,omitempty"`
	Fix         string           `json:"fix,omitempty"`
	FixRegex    *SemgrepFixRegex `json:"fix_regex,omitempty"`
	Dataflow    *SemgrepDataflow `json:"dataflow_trace,omitempty"`
}

// SemgrepMetadata contains rule metadata.
type SemgrepMetadata struct {
	CWE                interface{} `json:"cwe,omitempty"`
	OWASP              interface{} `json:"owasp,omitempty"`
	Confidence         string      `json:"confidence,omitempty"`
	Impact             string      `json:"impact,omitempty"`
	Likelihood         string      `json:"likelihood,omitempty"`
	Category           string      `json:"category,omitempty"`
	Subcategory        interface{} `json:"subcategory,omitempty"`
	Technology         interface{} `json:"technology,omitempty"`
	References         interface{} `json:"references,omitempty"`
	Source             string      `json:"source,omitempty"`
	SourceRuleURL      string      `json:"source-rule-url,omitempty"`
	VulnerabilityClass interface{} `json:"vulnerability_class,omitempty"`
}

// SemgrepFixRegex contains regex-based fix information.
type SemgrepFixRegex struct {
	Regex       string `json:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Count       int    `json:"count,omitempty"`
}

// SemgrepDataflow contains taint tracking data.
type SemgrepDataflow struct {
	TaintSource      []SemgrepDataflowLoc `json:"taint_source,omitempty"`
	IntermediateVars []SemgrepDataflowLoc `json:"intermediate_vars,omitempty"`
	TaintSink        []SemgrepDataflowLoc `json:"taint_sink,omitempty"`
}

// SemgrepDataflowLoc represents a location in a dataflow trace.
type SemgrepDataflowLoc struct {
	Content  string     `json:"content,omitempty"`
	Location SemgrepLoc `json:"location,omitempty"`
}

// SemgrepLoc is a file location in a dataflow trace.
type SemgrepLoc struct {
	Path  string     `json:"path,omitempty"`
	Start SemgrepPos `json:"start,omitempty"`
	End   SemgrepPos `json:"end,omitempty"`
}

// SemgrepError represents a Semgrep error.
type SemgrepError struct {
	Code    int    `json:"code,omitempty"`
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
	Type    string `json:"type,omitempty"`
}
