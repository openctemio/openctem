package bootstrapadmin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/admin"
)

// The verify-audit output, text and JSON, carries the chain head, so the
// export can be checked offline in Community.
func TestPrintAuditReportCarriesChainHead(t *testing.T) {
	r := &admin.AuditChainReport{Entries: 4, FirstPosition: 1, LastPosition: 4,
		Breaks: []admin.AuditChainBreak{}, Head: &admin.AuditChainHead{Position: 4, Hash: "abc123"}}

	var text bytes.Buffer
	printAuditReport(&text, r, false)
	if !strings.Contains(text.String(), "chain head: position 4  hash abc123") {
		t.Fatalf("text output has no head: %q", text.String())
	}

	var js bytes.Buffer
	printAuditReport(&js, r, true)
	var got struct {
		Head struct {
			Position int64  `json:"position"`
			Hash     string `json:"hash"`
		} `json:"head"`
	}
	if err := json.Unmarshal(js.Bytes(), &got); err != nil || got.Head.Position != 4 || got.Head.Hash != "abc123" {
		t.Fatalf("json head: %+v err=%v", got, err)
	}

	// An empty chain has no head to print.
	var empty bytes.Buffer
	printAuditReport(&empty, &admin.AuditChainReport{Breaks: []admin.AuditChainBreak{}}, false)
	if strings.Contains(empty.String(), "chain head") {
		t.Fatalf("empty chain printed a head: %q", empty.String())
	}
}
