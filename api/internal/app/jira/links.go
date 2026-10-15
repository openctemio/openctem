package jira

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
)

// Linking an existing tracker issue to a finding (research 157 K4). A link is
// created only by the platform (create ticket) or a person (here), never from
// a report, and only to an issue the tenant's own integration can see on its
// own site.

// ErrIssueNotVisible: the issue does not exist or the integration cannot see
// it. A validation error (400): the caller named it.
var ErrIssueNotVisible = fmt.Errorf("%w: the issue does not exist on the integration's site or the integration cannot see it", shared.ErrValidation)

// IssueIdentifier is what linking needs from a tracker client.
type IssueIdentifier interface {
	IntegrationID() shared.ID
	SiteURL() string
	IssueIdentity(ctx context.Context, issueKey string) (id, key string, err error)
}

// SetLinkStore wires the ticket link records.
func (s *SyncService) SetLinkStore(r ticketlink.Repository) { s.links = r }

// ErrLinksUnavailable: linking is not wired (no database) or the client
// cannot identify issues.
var ErrLinksUnavailable = fmt.Errorf("%w: linking an issue is not available", shared.ErrValidation)

// LinkExistingIssue links an existing issue (a key, or a browse URL on the
// integration's site) to a finding of the tenant.
func (s *SyncService) LinkExistingIssue(ctx context.Context, tenantID, findingID shared.ID, issue string, by *shared.ID) (*ticketlink.Link, error) {
	if s.links == nil {
		return nil, ErrLinksUnavailable
	}
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	ii, ok := client.(IssueIdentifier)
	if !ok {
		return nil, ErrLinksUnavailable
	}
	issue = strings.TrimSpace(issue)
	var key string
	if strings.Contains(issue, "://") {
		if key, err = ticketlink.KeyFromURL(ii.SiteURL(), issue); err != nil {
			return nil, err
		}
	} else {
		key = strings.ToUpper(issue)
		if !ticketlink.ValidKey(key) {
			return nil, fmt.Errorf("%w: give an issue key such as SEC-123 or its URL", shared.ErrValidation)
		}
	}
	id, current, err := ii.IssueIdentity(ctx, key)
	if err != nil {
		return nil, err
	}
	if ticketlink.ValidKey(current) {
		key = current // a moved issue answers with its new key
	}
	l, err := ticketlink.New(tenantID, ii.IntegrationID(), &findingID, nil, key, id,
		ii.SiteURL(), ticketlink.BrowseURL(ii.SiteURL(), key), ticketlink.RoleOwn, ticketlink.SourcePerson, by)
	if err != nil {
		return nil, err
	}
	if err := s.links.Create(ctx, l); err != nil {
		return nil, err
	}
	// The URL list stays the display copy (and the status sync's source until
	// it reads the links).
	if !containsFold(finding.WorkItemURIs(), l.URL) {
		finding.AddWorkItemURI(l.URL)
		if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, finding.WorkItemURIs()); err != nil {
			s.logger.Error("link issue: failed to update the finding's ticket list", "error", err)
		}
	}
	return l, nil
}

// UnlinkIssue removes a person's or the platform's link from a finding. The
// issue itself is left alone.
func (s *SyncService) UnlinkIssue(ctx context.Context, tenantID, findingID, linkID shared.ID) (*ticketlink.Link, error) {
	if s.links == nil {
		return nil, ErrLinksUnavailable
	}
	l, err := s.links.Get(ctx, tenantID, linkID)
	if err != nil {
		return nil, err
	}
	if l.FindingID == nil || *l.FindingID != findingID {
		return nil, ticketlink.ErrNotFound
	}
	if err := s.links.SetState(ctx, tenantID, linkID, ticketlink.StateUnlinked); err != nil {
		return nil, err
	}
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err == nil {
		kept := make([]string, 0, len(finding.WorkItemURIs()))
		for _, u := range finding.WorkItemURIs() {
			if !strings.EqualFold(u, l.URL) {
				kept = append(kept, u)
			}
		}
		if len(kept) != len(finding.WorkItemURIs()) {
			if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, kept); err != nil {
				s.logger.Error("unlink issue: failed to update the finding's ticket list", "error", err)
			}
		}
	}
	return l, nil
}

// FindingLinks lists a finding's links.
func (s *SyncService) FindingLinks(ctx context.Context, tenantID, findingID shared.ID) ([]*ticketlink.Link, error) {
	if s.links == nil {
		return []*ticketlink.Link{}, nil
	}
	return s.links.ListForFinding(ctx, tenantID, findingID)
}

// recordCreatedLink stores the link of an issue the platform just created.
// Best effort: the issue exists either way, and the URL list still names it.
func (s *SyncService) recordCreatedLink(ctx context.Context, client Client, tenantID, findingID shared.ID, res *CreateIssueResult, parent string) {
	if s.links == nil || res == nil {
		return
	}
	ii, ok := client.(IssueIdentifier)
	if !ok {
		return
	}
	role := ticketlink.RoleOwn
	if parent != "" {
		role = ticketlink.RoleSubtask
	}
	l, err := ticketlink.New(tenantID, ii.IntegrationID(), &findingID, nil, res.Key, res.ID,
		ii.SiteURL(), ticketlink.BrowseURL(ii.SiteURL(), res.Key), role, ticketlink.SourcePlatform, nil)
	if err == nil {
		err = s.links.Create(ctx, l)
	}
	if err != nil && !errors.Is(err, ticketlink.ErrAlreadyLinked) {
		s.logger.Error("create ticket: failed to record the link", "error", err, "ticket_key", res.Key)
	}
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
