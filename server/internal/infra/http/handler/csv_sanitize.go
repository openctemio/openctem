package handler

import "github.com/openctemio/openctem/server/pkg/safetext"

// sanitizeCSVCell defuses CSV formula injection (safetext.CSVCell, shared by
// every CSV the platform writes).
func sanitizeCSVCell(s string) string { return safetext.CSVCell(s) }

// sanitizeCSVRow applies sanitizeCSVCell to every element of row.
func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, v := range row {
		out[i] = sanitizeCSVCell(v)
	}
	return out
}
