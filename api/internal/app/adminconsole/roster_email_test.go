package adminconsole

import (
	"strings"
	"testing"
	"time"
)

func TestRosterChangeEmail(t *testing.T) {
	at := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	subject, body := RosterChangeEmail("Acme", RosterChange{
		Summary: "added x@example.com as Super admin", ActorEmail: "root@example.com\r\nBcc: evil@example.com", IP: "192.0.2.1", At: at,
	})
	if subject != "[Acme] Administrator change by root@example.comBcc: evil@example.com" {
		t.Fatalf("subject must stay on one line: %q", subject)
	}
	if !strings.Contains(body, "added x@example.com as Super admin in the Acme admin console.") {
		t.Fatalf("console notice body: %s", body)
	}
	_, body = RosterChangeEmail("", RosterChange{
		Summary: "replaced administrator <b>x</b>", ActorEmail: "bootstrap-admin", At: at,
		Via: "with the bootstrap-admin command on host ops-1",
	})
	if !strings.Contains(body, "replaced administrator &lt;b&gt;x&lt;/b&gt; with the bootstrap-admin command on host ops-1.") {
		t.Fatalf("command-line notice body must name where and escape: %s", body)
	}
}
