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
