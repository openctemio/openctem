package jira

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Duplicate-proof issue creation (research 220 P0-8,
// docs/architecture/ticketing-integration.md "Create idempotency"). Every
// issue the platform creates carries a marker in the create request itself:
// the issue property `openctem` = {"o": object id, "k": task|finding,
// "i": integration id} and the label `openctem-ref-<object id>` that makes
// it searchable. Before creating, the platform looks the object's marker up
// on the integration and adopts the issue it finds, so a create whose
// response was lost (a timeout after Jira created the issue) or whose link
// was not recorded is recovered by the next attempt instead of opening a
// second issue.

// Kinds of a marked object.
const (
	MarkerKindTask    = "task"
	MarkerKindFinding = "finding"
)

// IssueMarker names the OpenCTEM object an issue was created for.
type IssueMarker struct {
	Object      string // the object's id
	Kind        string // MarkerKindTask or MarkerKindFinding
	Integration string // the integration that created the issue
}

// MarkedIssue is an issue found by its marker label, with the marker
// property it carries ("" fields when it carries none).
type MarkedIssue struct {
	ID        string
	Key       string
	BrowseURL string
	Marker    IssueMarker
}

// MarkerFinder is a client that can look issues up by marker.
type MarkerFinder interface {
	FindIssuesByMarker(ctx context.Context, m IssueMarker) ([]MarkedIssue, error)
}

// markerFor is the marker of an object created through a client: nil when
// the client names no integration (then nothing can be verified, and
// nothing is adopted).
func markerFor(c Client, kind string, objectID shared.ID) *IssueMarker {
	var intg shared.ID
	switch v := c.(type) {
	case IssueIdentifier:
		intg = v.IntegrationID()
	case ProfileClient:
		intg = v.IntegrationID()
	default:
		return nil
	}
	if intg.IsZero() || objectID.IsZero() {
		return nil
	}
	return &IssueMarker{Object: objectID.String(), Kind: kind, Integration: intg.String()}
}

// findMarked returns the issue this integration already created for the
// object, or nil. An issue is adopted only when its marker property names
// exactly this object, kind and integration (a label copied onto another
// issue, or a marker of another object, tenant or integration, is never
// adopted) and accept allows its key (its project).
func (s *SyncService) findMarked(ctx context.Context, c Client, m *IssueMarker, accept func(key string) bool) (*CreateIssueResult, error) {
	if m == nil {
		return nil, nil
	}
	mf, ok := c.(MarkerFinder)
	if !ok {
		return nil, nil
	}
	hits, err := mf.FindIssuesByMarker(ctx, *m)
	if err != nil {
		// Without the lookup a retry could duplicate the issue: refuse
		// rather than guess (the create would reach the same site anyway).
		return nil, fmt.Errorf("look up an issue already created for this %s: %w", m.Kind, err)
	}
	for _, h := range hits {
		if h.Marker != *m || !ticketlink.ValidKey(h.Key) || (accept != nil && !accept(h.Key)) {
			if h.Marker.Object != "" && h.Marker != *m {
				s.logger.Warn("jira: an issue carries another object's marker; not adopted", "issue_key", logger.SanitizeValue(h.Key))
			}
			continue
		}
		s.logger.Info("jira: adopted the issue already created for the object", "kind", m.Kind, "issue_key", logger.SanitizeValue(h.Key))
		return &CreateIssueResult{ID: h.ID, Key: h.Key, BrowseURL: h.BrowseURL}, nil
	}
	return nil, nil
}
