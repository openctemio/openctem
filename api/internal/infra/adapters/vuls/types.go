// Package vuls provides an adapter to convert Vuls JSON output to CTIS.
package vuls

// VulsReport is the root Vuls JSON scan result.
type VulsReport struct {
	JSONVersion   int             `json:"jsonVersion"`
	ServerName    string          `json:"serverName"`
	Family        string          `json:"family"`
	Release       string          `json:"release"`
	RunningKernel VulsKernel      `json:"runningKernel"`
	ScannedAt     string          `json:"scannedAt"`
	ScannedVia    string          `json:"scannedVia"`
	ScannedIPv4   []string        `json:"scannedIpv4Addrs"`
	ScannedIPv6   []string        `json:"scannedIpv6Addrs"`
	Packages      VulsPackages    `json:"packages"`
	ScannedCves   []VulsCveResult `json:"scannedCves"`
}

// VulsKernel describes the running kernel.
type VulsKernel struct {
	Version        string `json:"version"`
	Release        string `json:"release"`
	RebootRequired bool   `json:"rebootRequired"`
}

// VulsPackages maps package name to package info.
type VulsPackages map[string]VulsPackage

// VulsPackage represents a package found on the server.
type VulsPackage struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Release    string `json:"release"`
	Arch       string `json:"arch"`
	Repository string `json:"repository"`
	NewVersion string `json:"newVersion"`
	NewRelease string `json:"newRelease"`
}

// VulsCveResult represents a CVE finding from Vuls.
type VulsCveResult struct {
	CveID            string            `json:"cveID"`
	Confidences      []VulsConfidence  `json:"confidences"`
	CveContents      VulsCveContents   `json:"cveContents"`
	AffectedPackages []VulsAffectedPkg `json:"affectedPackages"`
}

// VulsConfidence represents detection confidence.
type VulsConfidence struct {
	Score           int    `json:"score"`
	DetectionMethod string `json:"detectionMethod"`
}

// VulsCveContents maps source name to CVE content details.
type VulsCveContents map[string][]VulsCveContent

// VulsCveContent contains CVE details from a specific source.
type VulsCveContent struct {
	Type         string            `json:"type"`
	CveID        string            `json:"cveID"`
	Title        string            `json:"title"`
	Summary      string            `json:"summary"`
	Cvss3Score   float64           `json:"cvss3Score"`
	Cvss3Vector  string            `json:"cvss3Vector"`
	Cvss2Score   float64           `json:"cvss2Score"`
	Cvss2Vector  string            `json:"cvss2Vector"`
	Cvss40Score  float64           `json:"cvss40Score"`
	Cvss40Vector string            `json:"cvss40Vector"`
	CweIDs       []string          `json:"cweIDs"`
	References   []VulsRef         `json:"references"`
	Published    string            `json:"published"`
	LastModified string            `json:"lastModified"`
	SourceLink   string            `json:"sourceLink"`
	Optional     map[string]string `json:"optional"`
}

// VulsRef is a CVE reference link.
type VulsRef struct {
	Source string `json:"source"`
	Link   string `json:"link"`
	RefID  string `json:"refID"`
}

// VulsAffectedPkg represents a package affected by a CVE.
type VulsAffectedPkg struct {
	Name        string `json:"name"`
	FixedIn     string `json:"fixedIn"`
	NotFixedYet bool   `json:"notFixedYet"`
}
