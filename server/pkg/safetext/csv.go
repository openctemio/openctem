package safetext

import "strings"

// CSVCell defuses CSV formula injection, for every CSV the platform writes. A
// spreadsheet program interprets a cell starting with =, +, -, @, CR or TAB
// as a formula, which has let a malicious asset name or finding title run
// DDE/HYPERLINK payloads on the analyst's machine when an exported report is
// opened in Excel, LibreOffice or Numbers. Mitigation follows OWASP: prepend
// a single apostrophe to any cell whose first byte is in the trigger set.
//
// Leading whitespace does not protect a cell: spreadsheet importers trim it,
// so " =HYPERLINK(...)" is still a formula. The check skips it, like the web
// client's sanitizeCsvCell (RFC-040 §5.4).
func CSVCell(s string) string {
	if s == "" {
		return s
	}
	if s[0] == '\t' || s[0] == '\r' {
		return "'" + s
	}
	if trimmed := strings.TrimLeft(s, " \t\r\n\v\f"); trimmed != "" {
		switch trimmed[0] {
		case '=', '+', '-', '@':
			return "'" + s
		}
	}
	return s
}

// UnescapeCSVCell removes the apostrophe CSVCell added, so a file the
// platform exported imports back unchanged. Only an apostrophe CSVCell would
// have written is removed; any other leading apostrophe is the cell's own.
func UnescapeCSVCell(s string) string {
	if len(s) >= 2 && s[0] == '\'' && CSVCell(s[1:]) == s {
		return s[1:]
	}
	return s
}
