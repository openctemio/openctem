package handler

import (
	"strings"
	"testing"
)

func TestPreviewNotification(t *testing.T) {
	resp, err := previewNotification(NotificationPreviewRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Headline != "New exposure" || resp.ActionLabel != "Open exposure" || len(resp.Lines) == 0 || len(resp.Variables) == 0 {
		t.Fatalf("default preview: %+v", resp)
	}

	// The preview refuses what a save refuses, naming the variables.
	if _, err := previewNotification(NotificationPreviewRequest{MessageTemplate: "{severity_emoji} {timestamp} {title}"}); err == nil ||
		!strings.Contains(err.Error(), "severity_emoji, timestamp") {
		t.Fatalf("unknown variables: %v", err)
	}
	if _, err := previewNotification(NotificationPreviewRequest{MessageTemplate: "{title"}); err == nil {
		t.Fatal("unclosed brace accepted")
	}

	// Minimal: the template's asset variables render empty, never sample names.
	resp, err = previewNotification(NotificationPreviewRequest{DetailLevel: "minimal", MessageTemplate: "{asset}\n{title} for {organization}", Locale: "vi"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.Text, "example.com") || resp.Headline != "Điểm phơi nhiễm mới" {
		t.Fatalf("minimal preview: %+v", resp)
	}
}
