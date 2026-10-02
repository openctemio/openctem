// Package trivy provides an adapter to convert Trivy JSON output to CTIS.
package trivy

// TrivyReport is the root Trivy JSON document.
type TrivyReport struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName,omitempty"`
	ArtifactType  string         `json:"ArtifactType,omitempty"`
	Metadata      *TrivyMetadata `json:"Metadata,omitempty"`
	Results       []TrivyResult  `json:"Results"`
}

// TrivyMetadata contains scan metadata.
type TrivyMetadata struct {
	OS          *TrivyOS          `json:"OS,omitempty"`
	ImageID     string            `json:"ImageID,omitempty"`
	ImageConfig *TrivyImageConfig `json:"ImageConfig,omitempty"`
}

// TrivyOS describes the operating system.
type TrivyOS struct {
	Family string `json:"Family,omitempty"`
	Name   string `json:"Name,omitempty"`
}

// TrivyImageConfig holds container image configuration.
type TrivyImageConfig struct {
	Architecture string `json:"architecture,omitempty"`
}

// TrivyResult represents a scan result for a target.
type TrivyResult struct {
	Target            string               `json:"Target"`
	Class             string               `json:"Class,omitempty"`
	Type              string               `json:"Type,omitempty"`
	Vulnerabilities   []TrivyVulnerability `json:"Vulnerabilities,omitempty"`
	Misconfigurations []TrivyMisconfig     `json:"Misconfigurations,omitempty"`
	Secrets           []TrivySecret        `json:"Secrets,omitempty"`
}

// TrivyVulnerability represents a vulnerability finding.
type TrivyVulnerability struct {
	VulnerabilityID  string    `json:"VulnerabilityID"`
	PkgName          string    `json:"PkgName"`
	PkgPath          string    `json:"PkgPath,omitempty"`
	InstalledVersion string    `json:"InstalledVersion"`
	FixedVersion     string    `json:"FixedVersion,omitempty"`
	Severity         string    `json:"Severity"`
	Title            string    `json:"Title,omitempty"`
	Description      string    `json:"Description,omitempty"`
	PrimaryURL       string    `json:"PrimaryURL,omitempty"`
	DataSource       *TrivyDS  `json:"DataSource,omitempty"`
	CVSS             TrivyCVSS `json:"CVSS,omitempty"`
	CweIDs           []string  `json:"CweIDs,omitempty"`
	References       []string  `json:"References,omitempty"`
	PublishedDate    string    `json:"PublishedDate,omitempty"`
	LastModifiedDate string    `json:"LastModifiedDate,omitempty"`
	Status           string    `json:"Status,omitempty"`
}

// TrivyDS is a Trivy data source.
type TrivyDS struct {
	ID   string `json:"ID,omitempty"`
	Name string `json:"Name,omitempty"`
	URL  string `json:"URL,omitempty"`
}

// TrivyCVSS maps CVSS source to score data.
type TrivyCVSS map[string]TrivyCVSSData

// TrivyCVSSData contains CVSS scoring details.
type TrivyCVSSData struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

// TrivyMisconfig represents a misconfiguration finding.
type TrivyMisconfig struct {
	Type          string          `json:"Type,omitempty"`
	ID            string          `json:"ID,omitempty"`
	AVDID         string          `json:"AVDID,omitempty"`
	Title         string          `json:"Title,omitempty"`
	Description   string          `json:"Description,omitempty"`
	Message       string          `json:"Message,omitempty"`
	Namespace     string          `json:"Namespace,omitempty"`
	Query         string          `json:"Query,omitempty"`
	Resolution    string          `json:"Resolution,omitempty"`
	Severity      string          `json:"Severity"`
	PrimaryURL    string          `json:"PrimaryURL,omitempty"`
	References    []string        `json:"References,omitempty"`
	Status        string          `json:"Status,omitempty"`
	CauseMetadata *TrivyCauseMeta `json:"CauseMetadata,omitempty"`
}

// TrivyCauseMeta contains location details for misconfigurations.
type TrivyCauseMeta struct {
	Resource  string     `json:"Resource,omitempty"`
	Provider  string     `json:"Provider,omitempty"`
	Service   string     `json:"Service,omitempty"`
	StartLine int        `json:"StartLine,omitempty"`
	EndLine   int        `json:"EndLine,omitempty"`
	Code      *TrivyCode `json:"Code,omitempty"`
}

// TrivyCode contains the code snippet details.
type TrivyCode struct {
	Lines []TrivyCodeLine `json:"Lines,omitempty"`
}

// TrivyCodeLine is a single line of code.
type TrivyCodeLine struct {
	Number  int    `json:"Number,omitempty"`
	Content string `json:"Content,omitempty"`
}

// TrivySecret represents a secret finding from Trivy.
type TrivySecret struct {
	RuleID    string `json:"RuleID,omitempty"`
	Category  string `json:"Category,omitempty"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title,omitempty"`
	StartLine int    `json:"StartLine,omitempty"`
	EndLine   int    `json:"EndLine,omitempty"`
	Match     string `json:"Match,omitempty"`
}
