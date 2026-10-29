package coverage

import (
	"strings"
	"testing"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
)

// The unreachable alert names the capability and a count, never a target.
func TestDescribeCondition_Unreachable(t *testing.T) {
	title, body, url := describeAlert([]covdom.AlertCondition{{Capability: "probe.http", Kind: covdom.AlertUnreachable, Count: 7}})
	if title != "Coverage: probe.http targets unreachable" {
		t.Fatalf("title %q", title)
	}
	if !strings.HasPrefix(body, "7 assets did not answer probe.http from your sensors;") || !strings.Contains(body, "Check that a sensor") {
		t.Fatalf("body %q", body)
	}
	if url != "/assets" {
		t.Fatalf("url %q", url)
	}
}
