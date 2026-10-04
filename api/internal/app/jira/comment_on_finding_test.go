package jira

import (
	"context"
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
