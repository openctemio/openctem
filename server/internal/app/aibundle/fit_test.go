package aibundle

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/internal/app/aipolicy"
	"github.com/openctemio/openctem/server/pkg/aimask"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

func bigBundle(t *testing.T, description string) *Bundle {
	t.Helper()
	tenantID := shared.NewID()
	f := newFinding(t, tenantID, vulnerability.FindingSourceDAST)
	f.SetDescription(description)
	b, err := NewBuilder(nil).Build(context.Background(), Input{TenantID: tenantID, Finding: f, Ceiling: aipolicy.ClassInternal,
		Policy: aimask.FullPolicy(), RunKey: key(t),
		Asset:     &Asset{Name: "portal.example.com", Type: "domain", Identifiers: []string{"10.20.30.40"}},
		Knowledge: []Excerpt{{Ordinal: 1, Title: "Runbook", Body: strings.Repeat("Rotate the key. ", 50), Updated: "2026-11-01"}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFit_LeavesAFittingBundleAlone(t *testing.T) {
	b := bigBundle(t, "Short.")
	text, digest := b.Text, b.Digest
	shortened, ok := b.Fit(func(string) bool { return true })
	if !ok || len(shortened) != 0 || b.Text != text || b.Digest != digest {
		t.Fatalf("a fitting bundle changed: ok=%v shortened=%v", ok, shortened)
	}
}

func TestFit_DropsKnowledgeThenShortensTheLongestField(t *testing.T) {
	b := bigBundle(t, strings.Repeat("The service answers on portal.example.com with TLS 1.0. ", 400))
	before := b.Digest
	const limit = 3000
	fits := func(s string) bool { return utf8.RuneCountInString(s) <= limit }
	shortened, ok := b.Fit(fits)
	if !ok || !fits(b.Text) {
		t.Fatalf("bundle does not fit: ok=%v len=%d", ok, utf8.RuneCountInString(b.Text))
	}
	if len(b.Knowledge) != 0 || len(b.KnowledgeRefs) != 0 || strings.Contains(b.Text, "kb:1") {
		t.Fatalf("knowledge kept although the bundle was too large: %v", b.KnowledgeRefs)
	}
	if len(shortened) != 1 || shortened[0] != aipolicy.FieldFindingDescription {
		t.Fatalf("shortened %v, want the description", shortened)
	}
	// Said in the text, still a field the run sent, still masked.
	if !strings.Contains(b.Text, ShortenedMark) || !strings.Contains(b.Text, "shortened the value of finding.description") {
		t.Fatalf("the shortening is not stated in the text:\n%s", b.Text)
	}
	if !containsField(b.FieldsSent, aipolicy.FieldFindingDescription) {
		t.Fatalf("a shortened field left the fields sent: %v", b.FieldsSent)
	}
	if strings.Contains(b.Text, "portal.example.com") {
		t.Fatal("a real value reached the fitted bundle")
	}
	if b.Digest == before || !strings.HasPrefix(b.Digest, "sha256:") {
		t.Fatal("the digest does not describe the fitted bundle")
	}
}

func TestFit_WithholdsWhatCannotBeShortenedEnough(t *testing.T) {
	b := bigBundle(t, strings.Repeat("x", 5000))
	b.Knowledge, b.KnowledgeRefs = nil, nil
	b.Text, _ = render(b, false)
	// Room for about 30 runes of the description: too little to keep, so it
	// is withheld (the rest of the bundle fits once it is gone).
	limit := utf8.RuneCountInString(b.Text) - 5000 + len("- The platform shortened the value of finding.description to fit the job.\n") +
		len(ShortenedMark) + 30
	_, ok := b.Fit(func(s string) bool { return utf8.RuneCountInString(s) <= limit })
	if !ok {
		t.Fatal("the bundle could not be fitted")
	}
	if !containsField(b.FieldsWithheld, aipolicy.FieldFindingDescription) || containsField(b.FieldsSent, aipolicy.FieldFindingDescription) {
		t.Fatalf("description neither sent whole nor withheld: sent %v withheld %v", b.FieldsSent, b.FieldsWithheld)
	}
	if !strings.Contains(b.Text, "left out finding.description") {
		t.Fatalf("the withheld field is not stated:\n%s", b.Text)
	}
}

func TestFit_ReportsABundleThatCannotFit(t *testing.T) {
	b := bigBundle(t, "Short.")
	if _, ok := b.Fit(func(string) bool { return false }); ok {
		t.Fatal("Fit reported success for a limit nothing meets")
	}
}
