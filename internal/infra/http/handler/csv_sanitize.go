package handler

// sanitizeCSVCell defuses CSV formula injection. A spreadsheet program
// interprets a cell starting with =, +, -, @, CR, or TAB as a formula,
// which has historically allowed a malicious asset name or finding
// title to execute DDE/HYPERLINK payloads on the analyst's machine
// when an exported report is opened in Excel/LibreOffice/Numbers.
// Mitigation follows OWASP: prepend a single apostrophe to any cell
// whose first byte is in the trigger set.
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
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
