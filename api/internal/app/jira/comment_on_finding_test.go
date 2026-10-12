package jira

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-039: a retest or a scan comments on the finding's linked Jira issue when
// it is fixed or seen again. Outbound writes are opt-in per integration, like
// status sync.
func TestCommentOnFinding_CommentsWhenSyncEnabled(t *testing.T) {
	c := &recordingClient{}
	s := newSync(&stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: enabledMapping()})
	if err := s.CommentOnFinding(context.Background(), shared.NewID(), shared.NewID(), "Regression: seen again"); err != nil {
		t.Fatal(err)
	}
	if len(c.comments) != 1 || c.comments[0] != "Regression: seen again" {
		t.Fatalf("comments = %v", c.comments)
	}
}

func TestCommentOnFinding_NoopWhenSyncDisabledUnlinkedOrUnconfigured(t *testing.T) {
	cases := map[string]struct {
		url      string
		resolver MappingResolver
	}{
		"sync disabled":   {"https://x.atlassian.net/browse/SEC-7", stubMappingResolver{mapping: DefaultMappingConfig()}},
		"not linked":      {"", stubMappingResolver{mapping: enabledMapping()}},
		"no integration":  {"https://x.atlassian.net/browse/SEC-7", stubMappingResolver{err: ErrNoTicketingIntegration}},
		"no resolver set": {"https://x.atlassian.net/browse/SEC-7", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := &recordingClient{}
			s := newSync(&stubFindingRepo{finding: findingInProgress(t, tc.url)}, c)
			if tc.resolver != nil {
				s.SetMappingResolver(tc.resolver)
			}
			if err := s.CommentOnFinding(context.Background(), shared.NewID(), shared.NewID(), "x"); err != nil {
				t.Fatal(err)
			}
			if len(c.comments) != 0 {
				t.Fatalf("commented although it must not: %v", c.comments)
			}
		})
	}
}

// A comment carries values a sensor controls (the finding title, a retest
// reason): they must reach Jira as text, never as wiki markup.
func TestCommentOnFinding_EncodesWikiMarkup(t *testing.T) {
	c := &recordingClient{}
	s := newSync(&stubFindingRepo{finding: findingInProgress(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: enabledMapping()})
	title := `[Re-authenticate|https://evil.test/login] !https://evil.test/px.png! [~admin] {html}<b>x</b>{html}`
	body := "Regression: \"" + title + "\" was detected again\n\nreason: see https://evil.test\n\nObserved by OpenCTEM."
	if err := s.CommentOnFinding(context.Background(), shared.NewID(), shared.NewID(), body); err != nil {
		t.Fatal(err)
	}
	if len(c.comments) != 1 {
		t.Fatalf("comments = %v", c.comments)
	}
	got := c.comments[0]
	if strings.Contains(got, "https://") {
		t.Fatalf("a URL is still clickable: %s", got)
	}
	// Every wiki markup character is escaped (preceded by a backslash).
	prev := ' '
	for _, r := range got {
		if strings.ContainsRune("[]|!{}~", r) && prev != '\\' {
			t.Fatalf("unescaped %q in the comment: %s", r, got)
		}
		prev = r
	}
	if strings.Count(got, "\n\n") != 2 {
		t.Fatalf("paragraphs not kept: %q", got)
	}
}
