package scansession

import "strings"

// scannerTypes are the values the scan_sessions.scanner_type CHECK constraint
// accepts, plus the names sdk-go's core.ScannerType uses for the same kinds.
var scannerTypes = map[string]string{
	"sast":             "sast",
	"sca":              "sca",
	"secret":           "secret",
	"container":        "container",
	"iac":              "iac",
	"dast":             "dast",
	"recon":            "recon",
	"dependency":       "sca",
	"secret_detection": "secret",
	"secrets":          "secret",
}

// NormalizeScannerType maps a sensor-reported scanner type to the stored
// value. Empty input is valid and stays empty (stored as NULL). An unknown
// type returns "" and false: the field is a classification, so a type the
// platform does not know is dropped rather than failing the scan.
func NormalizeScannerType(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", true
	}
	t, ok := scannerTypes[v]
	return t, ok
}
