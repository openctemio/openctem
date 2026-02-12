package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Output format constants.
const (
	outputJSON = "json"
	outputYAML = "yaml"
	outputWide = "wide"
)

func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: marshal JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func printYAML(v any) {
	data, err := yaml.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: marshal YAML: %v\n", err)
		return
	}
	fmt.Print(string(data))
}

func unmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}

type tableWriter struct {
	w       *tabwriter.Writer
	headers []string
}

func newTable(headers ...string) *tableWriter {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	t := &tableWriter{w: w, headers: headers}
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	return t
}

func (t *tableWriter) AddRow(values ...string) {
	fmt.Fprintln(t.w, strings.Join(values, "\t"))
}

func (t *tableWriter) Flush() {
	t.w.Flush()
}

func printPagination(total int64, page, perPage, totalPages int) {
	if total == 0 {
		fmt.Println("No resources found.")
		return
	}
	start := (page-1)*perPage + 1
	end := page * perPage
	if int64(end) > total {
		end = int(total)
	}
	fmt.Printf("\nShowing %d-%d of %d results (page %d/%d)\n", start, end, total, page, totalPages)
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func ptrStr(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func shortTime(t string) string {
	if len(t) >= 19 {
		return t[:19]
	}
	return t
}

func successStr(s bool) string {
	if s {
		return "OK"
	}
	return "FAIL"
}
