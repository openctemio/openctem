package ingest

import "strings"

// maxLogValue caps a report-supplied value written to the log.
const maxLogValue = 256

// logValue makes a report-supplied string safe to log: no line breaks (a
// sensor must not be able to forge log lines) and a bounded length.
func logValue(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > maxLogValue {
		s = s[:maxLogValue]
	}
	return s
}
