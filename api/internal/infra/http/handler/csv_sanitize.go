package handler

import "strings"

// sanitizeCSVCell defuses CSV formula injection. A spreadsheet program
// interprets a cell starting with =, +, -, @, CR, or TAB as a formula,
// which has historically allowed a malicious asset name or finding
// title to execute DDE/HYPERLINK payloads on the analyst's machine
// when an exported report is opened in Excel/LibreOffice/Numbers.
// Mitigation follows OWASP: prepend a single apostrophe to any cell
// whose first byte is in the trigger set.
//
// Leading whitespace does not protect a cell: spreadsheet importers trim
// it, so " =HYPERLINK(...)" is still a formula. The check skips it, like
// the web client's sanitizeCsvCell (RFC-040 §5.4).
func sanitizeCSVCell(s string) string {
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

// sanitizeCSVRow applies sanitizeCSVCell to every element of row.
func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, v := range row {
		out[i] = sanitizeCSVCell(v)
	}
	return out
}
