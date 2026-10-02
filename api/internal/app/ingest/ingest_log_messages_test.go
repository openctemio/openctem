package ingest

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func bufferLogger() (*logger.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return logger.New(logger.Config{Level: "debug", Format: "text", Output: &buf}), &buf
}

// A report with neither assets nor findings has nothing to orphan; warning
// "findings will be orphaned" for it is noise (every clean scan, every empty
// chunk). The warning stays for a report that does carry findings.
func TestProcessBatch_OrphanWarningOnlyWhenThereAreFindings(t *testing.T) {
	log, buf := bufferLogger()
	p := NewAssetProcessor(nil, log)

	if _, err := p.ProcessBatch(context.Background(), shared.NewID(), &ctis.Report{}, &Output{}, nil); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if strings.Contains(buf.String(), "orphaned") {
		t.Fatalf("empty report logged an orphan warning:\n%s", buf.String())
	}
}

// When the report qualifies for auto-resolve and only the sensor/tool gate
// refuses it, the skip must not be explained as "coverage type not full": the
// scan WAS full coverage.
func TestLogAutoResolveSkipped(t *testing.T) {
	full := &ctis.Report{
		Tool:     &ctis.Tool{Name: "trivy"},
		Metadata: ctis.ReportMetadata{ID: "scan-1", CoverageType: "full", Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}},
	}
	partial := &ctis.Report{
		Tool:     &ctis.Tool{Name: "trivy"},
		Metadata: ctis.ReportMetadata{ID: "scan-1", CoverageType: "incremental", Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}},
	}
	feature := &ctis.Report{
		Tool:     &ctis.Tool{Name: "trivy"},
		Metadata: ctis.ReportMetadata{ID: "scan-1", CoverageType: "full", Branch: &ctis.BranchInfo{Name: "feat"}},
	}

	cases := []struct {
		name      string
		report    *ctis.Report
		gate      bool
		want      string
		forbidden string
	}{
		{"tool gate refused a full default-branch scan", full, true, "", "coverage type not full"},
		{"incremental scan", partial, false, "coverage type not full", ""},
		{"feature branch", feature, false, "not default branch", "coverage type not full"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log, buf := bufferLogger()
			s := &Service{logger: log}
			s.logAutoResolveSkipped(Input{Report: tc.report}, tc.report, tc.gate)
			out := buf.String()
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("want %q in log, got:\n%s", tc.want, out)
			}
			if tc.forbidden != "" && strings.Contains(out, tc.forbidden) {
				t.Errorf("log wrongly says %q:\n%s", tc.forbidden, out)
			}
		})
	}
}
