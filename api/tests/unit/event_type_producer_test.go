package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
)

// producerFile marks files that hand an event to the notification outbox or
// to a channel.
var producerFile = regexp.MustCompile(`EnqueueParams\{|EnqueueNotificationParams\{|SendNotificationInput\{|BroadcastNotificationInput\{`)

// Every event type a notification channel can subscribe to must have a
// producer. A type nothing emits is a checkbox that delivers nothing, and
// security_alert was even on by default (settings plan P0-08, 23b §3).
//
// A producer is a non-test file outside the catalog that enqueues or sends a
// notification and names the type's constant (EventTypeX) or spells its id as
// a string literal.
func TestEveryCatalogEventTypeHasAProducer(t *testing.T) {
	root := repoRoot(t)
	catalog := filepath.Join(root, "pkg", "domain", "integration", "notification_extension.go")
	src, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	constOf := map[string]string{} // id -> constant name
	for _, m := range regexp.MustCompile(`(?m)^\s+(EventType[A-Za-z]+)\s+EventType = "([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		constOf[m[2]] = m[1]
	}

	var corpus strings.Builder
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		if err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || p == catalog {
				return nil
			}
			b, _ := os.ReadFile(p)
			// Only files that hand an event to the notification outbox or a
			// channel count; the in-app inbox and workflow triggers reuse some
			// of the same words for other vocabularies.
			if !producerFile.Match(b) {
				return nil
			}
			// Struct-tag examples and SQL defaults are not producers.
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "example:") || strings.Contains(line, "COALESCE(") {
					continue
				}
				corpus.WriteString(line)
				corpus.WriteByte('\n')
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	text := corpus.String()

	for _, info := range integration.AllEventTypes() {
		id := string(info.Type)
		name := constOf[id]
		if strings.Contains(text, `"`+id+`"`) || (name != "" && regexp.MustCompile(`\b`+name+`\b`).MatchString(text)) {
			continue
		}
		t.Errorf("event type %q is in the catalog but nothing emits it; remove it from AllEventTypes or add its producer", id)
	}
	for _, id := range integration.DefaultEnabledEventTypes() {
		found := false
		for _, info := range integration.AllEventTypes() {
			if info.Type == id {
				found = true
			}
		}
		if !found {
			t.Errorf("default event type %q is not in the catalog", id)
		}
	}
}
