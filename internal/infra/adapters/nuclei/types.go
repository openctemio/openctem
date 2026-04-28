// Package nuclei provides an adapter to convert Nuclei JSONL output to CTIS.
package nuclei

// NucleiResult represents a single Nuclei finding (one JSON object per line).
type NucleiResult struct {
	TemplateID       string     `json:"template-id"`
	TemplatePath     string     `json:"template,omitempty"`
	Info             NucleiInfo `json:"info"`
	Type             string     `json:"type"`
	Host             string     `json:"host"`
	MatchedAt        string     `json:"matched-at"`
	ExtractedResults []string   `json:"extracted-results,omitempty"`
	IP               string     `json:"ip,omitempty"`
	Timestamp        string     `json:"timestamp,omitempty"`
	CurlCommand      string     `json:"curl-command,omitempty"`
	MatcherName      string     `json:"matcher-name,omitempty"`
	MatcherStatus    bool       `json:"matcher-status,omitempty"`
	TemplateURL      string     `json:"template-url,omitempty"`
}

// NucleiInfo contains template metadata.
type NucleiInfo struct {
	Name           string                 `json:"name"`
	Severity       string                 `json:"severity"`
	Description    string                 `json:"description,omitempty"`
	Author         interface{}            `json:"author,omitempty"`
	Tags           interface{}            `json:"tags,omitempty"`
	Reference      interface{}            `json:"reference,omitempty"`
	Classification *NucleiClassification  `json:"classification,omitempty"`
	Remediation    string                 `json:"remediation,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// NucleiClassification contains vulnerability classification.
type NucleiClassification struct {
	CVEID       interface{} `json:"cve-id,omitempty"`
	CWEID       interface{} `json:"cwe-id,omitempty"`
	CVSSMetrics string      `json:"cvss-metrics,omitempty"`
	CVSSScore   float64     `json:"cvss-score,omitempty"`
	EPSSP       float64     `json:"epss-score,omitempty"`
	EPSSPerc    float64     `json:"epss-percentile,omitempty"`
	CPE         string      `json:"cpe,omitempty"`
}
