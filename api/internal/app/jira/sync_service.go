package jira

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// ticketDescription builds the Jira description for a finding. What text
// may leave is the outbound gate's decision (ticketing.FindingContent): a
// secret finding sends its location only (no description, preview, snippet,
// fingerprint or commit context), a finding that exposes data sends no free
// text at all. Every other description is secret-redacted as defense in depth.
//
// The description is Jira wiki markup (REST API v2), and every value that
// comes from the finding is attacker-influenced (a scanned page title, a file
// path, a sensor report). Each one is redacted first, then encoded: one-line
// values are escaped, the description goes into a {noformat} block, and URLs
// are defanged, so the text cannot add links, mentions, images or macros to
// the ticket (RFC-040 §5.4).
func ticketDescription(f *vulnerability.Finding) string {
	inline := func(s string) string {
		return safetext.JiraWikiInline(safetext.RedactSecrets(s), safetext.MaxInlineRunes)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*Finding:* %s\n*Severity:* %s\n*Status:* %s\n",
		inline(ticketing.OutboundTitle(f)), inline(string(f.Severity())), inline(string(f.Status())))
	if f.FilePath() != "" {
		fmt.Fprintf(&b, "*Location:* %s:%d\n", inline(vulnerability.DisplayPath(f.FilePath())), f.StartLine())
	}

	switch ticketing.FindingContent(f) {
	case ticketing.ContentSecret:
		b.WriteString("\nA secret was detected. Its value is not sent to trackers. Open the finding in the platform for full details.")
		return withMobilizationBrief(b.String(), f)
	case ticketing.ContentPersonalData:
		b.WriteString("\nThis finding exposes data. Its details are not sent to trackers. Open the finding in the platform for full details.")
		return b.String()
	case ticketing.ContentFull:
	}

	if desc := strings.TrimSpace(f.Description()); desc != "" {
		b.WriteString("\n")
		b.WriteString(safetext.JiraWikiBlock(safetext.RedactSecrets(desc), safetext.MaxDescriptionRunes))
	}
	return withMobilizationBrief(b.String(), f)
}

// ticketSummary is the Jira summary (plain text, one line, at most 255
// characters in Jira): the title with its target ("[high] CVE-2019-9516 in
// nginx 1.15.5 on 10.20.30.41:443"), secret-redacted, cleaned of control and
// bidi characters, folded to one line and capped.
func ticketSummary(f *vulnerability.Finding, assetName string) string {
	return safetext.SingleLine(safetext.RedactSecrets(fmt.Sprintf("[%s] %s", f.Severity(), ticketing.OutboundDisplayTitle(f, assetName))), safetext.MaxTitleRunes)
}

// withMobilizationBrief appends the CTEM Mobilization brief (definition of done
// + acceptable fixes) to a ticket body when the finding carries one. The brief
// is written by people with write access, so it is treated like any other
// text that leaves the platform: secret-redacted, capped, and placed in a
// {noformat} block so it cannot add links, mentions, images or macros.
func withMobilizationBrief(body string, f *vulnerability.Finding) string {
	brief := strings.TrimSpace(f.Remediation().MobilizationBrief())
	if brief == "" {
		return body
	}
	return body + "\n\n" + safetext.JiraWikiBlock(safetext.RedactSecrets(brief), safetext.MaxBriefRunes)
}

// Client defines the interface for Jira REST API operations.
type Client interface {
	CreateIssue(ctx context.Context, input CreateIssueInput) (*CreateIssueResult, error)
	// GetIssueStatus returns the issue's current status name (echo-guard).
	GetIssueStatus(ctx context.Context, issueKey string) (string, error)
	// TransitionToStatus moves the issue to a target status NAME, attaching an
	// optional comment. Returns ErrNoMatchingTransition when the workflow offers
	// no transition to that status (caller falls back to AddComment).
	TransitionToStatus(ctx context.Context, issueKey, targetStatus, comment string) error
	// AddComment posts a comment on the issue.
	AddComment(ctx context.Context, issueKey, body string) error
	// ListProjects returns the projects visible to the configured credentials,
	// for the admin project picker (so an operator chooses the destination
	// project from a list instead of typing a key). Paginated server-side.
	ListProjects(ctx context.Context) ([]ProjectRef, error)
	TestConnection(ctx context.Context) error
}

// ProjectRef is a Jira project as surfaced to the admin project picker.
type ProjectRef struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// ErrNoMatchingTransition mirrors the infra client's sentinel at the app layer
// (the adapter maps the infra error to this one) so SyncService can fall back to
// a comment without importing the infra package.
var ErrNoMatchingTransition = errors.New("no jira transition to target status")

// ClientResolver builds a Jira Client for a given tenant from that tenant's
// configured ticketing integration (base URL + decrypted credentials). It is
// the outbound counterpart to the inbound webhook path: without a resolver the
// SyncService has no client and CreateTicketFromFinding is inert.
//
// Implementations live in the infra layer (they decrypt credentials and open
// HTTP clients). Returning ErrNoTicketingIntegration means the tenant has no
// usable Jira integration — callers surface that as a 4xx, not a 5xx.
type ClientResolver interface {
	// Resolve returns the client of the tenant's default Jira integration
	// (for a create that names no integration).
	Resolve(ctx context.Context, tenantID shared.ID) (Client, error)
	// ResolveByID returns the client of one named Jira integration of the
	// tenant, which must be connected. Every call that acts on an existing
	// link or an inbound delivery uses it: the link or the delivery names
	// its integration, and a tenant may connect several Jira sites.
	ResolveByID(ctx context.Context, tenantID, integrationID shared.ID) (Client, error)
}

// MappingResolver loads a tenant's ticketing MappingConfig (status maps +
// sync_enabled) from its integration config. Counterpart to ClientResolver,
// used by outbound status sync to decide whether/where to push. Returning
// ErrNoTicketingIntegration means the tenant has no Jira integration.
type MappingResolver interface {
	ResolveMapping(ctx context.Context, tenantID shared.ID) (MappingConfig, error)
	// ResolveMappingByID loads the mapping of one named Jira integration of
	// the tenant, in any status (an inbound delivery of an integration whose
	// token expired still moves its own links), with SiteURL set.
	ResolveMappingByID(ctx context.Context, tenantID, integrationID shared.ID) (MappingConfig, error)
}

// ErrNoTicketingIntegration is returned by a ClientResolver when the tenant has
// no connected Jira integration to create tickets against. It wraps
// ErrValidation so the HTTP layer maps it to a 400 rather than a 500.
var ErrNoTicketingIntegration = fmt.Errorf("%w: no connected Jira integration configured for this tenant", shared.ErrValidation)

// CreateIssueInput contains fields for creating a Jira issue.
type CreateIssueInput struct {
	ProjectKey  string
	Summary     string
	Description string
	// IssueType is the issue type's name; IssueTypeID, when set, wins (the
	// type is then sent by id).
	IssueType   string
	IssueTypeID string
	Priority    string
	Labels      []string
	// ParentKey makes the issue a child of this issue (an epic).
	ParentKey string
	// Marker is written into the create request (see IssueMarker).
	Marker *IssueMarker
}

// CreateIssueResult contains the response from creating a Jira issue.
type CreateIssueResult struct {
	ID        string
	Key       string
	BrowseURL string
}

// SyncService handles bidirectional sync between findings and Jira tickets.
//
// Capabilities:
//  1. POST /findings/{id}/link-ticket     — manually link a Jira ticket to a finding
//  2. POST /findings/{id}/create-ticket   — auto-create Jira ticket from finding
//  3. POST /webhooks/incoming/jira        — receive Jira status-change webhooks
type SyncService struct {
	findingRepo vulnerability.FindingRepository
	jiraClient  Client
	logger      *logger.Logger
	// egress is the outbound gate (egress.go); nil refuses pentest content.
	egress *ticketing.EgressGate

	// clientResolver builds a per-tenant Jira client on demand. When set, it
	// takes precedence over the static jiraClient (which exists mainly so tests
	// can inject a stub). In production jiraClient is nil and the resolver loads
	// the tenant's integration credentials per request.
	clientResolver ClientResolver

	// mappingResolver loads the per-tenant status maps + sync_enabled flag for
	// outbound sync (SyncFindingStatus). nil → outbound sync is inert.
	mappingResolver MappingResolver

	// assetRouteResolver supplies a finding's asset attributes (scope,
	// criticality, groups) so routing rules can match on them. nil → routing
	// matches only on finding-level fields (severity, tags).
	assetRouteResolver AssetRouteResolver

	// B3: optional hook fired when a Jira webhook transitions
	// a finding into `fix_applied`. Wired to the verification-scan
	// trigger to close the "Jira Done → auto rescan" feedback edge
	// without a manual Verify button click.
	postFixHook FixAppliedHook

	// activity records inbound status changes with the integration as actor.
	activity StatusActivityRecorder

	// applier, workItems and refusalGuard serve inbound status changes.
	applier      InboundStatusApplier
	workItems    WorkItemFindingLister
	refusalGuard RefusalCommentGuard
	// links stores ticket link records (nil → URL strings only).
	links ticketlink.Repository

	// taskAccess and taskReader serve task issues; webBase links back.
	taskAccess TaskAccess
	taskReader TaskReader
	webBase    string

	// profiles renders published ticket mapping profiles (nil → built-in
	// fields and status sync only).
	profiles ProfileSource
	// typeHealth records create refusals of a kind on the integration.
	typeHealth IssueTypeHealth

	// campaignSink receives inbound epic status changes so a linked remediation
	// campaign can be completed (epic Done → campaign completed). nil → inbound
	// campaign sync is inert.
	campaignSink CampaignEpicSink
}

// CampaignEpicSink receives inbound Jira epic status changes so a linked
// remediation campaign can react (e.g. epic Done → campaign completed).
// Implemented by *exposure.RemediationCampaignService. Declared here so the
// jira package needs no dependency on the remediation/exposure packages.
type CampaignEpicSink interface {
	// HandleEpicStatusChange reacts to the linked epic of a campaign moving
	// in Jira. It returns the refusals to comment back on the epic (one line
	// per finding the rules kept where it is), and handled=false when the
	// issue is not a campaign epic. site is the base URL of the integration
	// the delivery came from: only an epic on that site matches.
	HandleEpicStatusChange(ctx context.Context, tenantID shared.ID, site, issueKey, jiraStatus, jiraAccount string) (refusals []string, handled bool, err error)
}

// InboundRefusal is one finding an inbound ticket change did not move, with
// the reason.
type InboundRefusal struct {
	FindingID string
	Reason    string
}

// InboundStatusApplier applies a linked ticket's status to findings through
// the finding service rules (finding.VulnerabilityService.ApplyTicketStatus):
// transition map, approval and pentest gates, "mark fixed" with proof of
// fix. Never a direct repository write.
type InboundStatusApplier interface {
	ApplyTicketStatus(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
		target vulnerability.FindingStatus, integration, ref, externalActor string) (applied []shared.ID, refused []InboundRefusal, err error)
	// RequestTicketDisposition opens a pending risk-acceptance or
	// false-positive request for each linked finding (four-eyes; never a
	// close). pending are findings that already had a pending request.
	RequestTicketDisposition(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID,
		target vulnerability.FindingStatus, integration, ref, externalActor string) (requested, pending []shared.ID, refused []InboundRefusal, err error)
}

// WorkItemFindingLister lists every finding of the tenant linked to a ticket
// URL (a ticket may track several findings).
type WorkItemFindingLister interface {
	ListIDsByWorkItemURI(ctx context.Context, tenantID shared.ID, uri string, limit int) ([]shared.ID, error)
}

// RefusalCommentGuard deduplicates refusal comments (FirstDelivery is true
// once per key and window), so a retried or repeated delivery comments once.
type RefusalCommentGuard interface {
	FirstDelivery(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// maxInboundFindings bounds how many findings one ticket may move.
const maxInboundFindings = 500

// refusalCommentWindow is how long an identical refusal comment is not
// repeated on the same issue.
const refusalCommentWindow = time.Hour

// maxRefusalLines bounds the refusal comment.
const maxRefusalLines = 20

// SetInboundApplier wires the finding service path for inbound changes. Without
// it, inbound status changes are not applied (fail closed).
func (s *SyncService) SetInboundApplier(a InboundStatusApplier) { s.applier = a }

// SetWorkItemFindingLister wires the all-findings-of-a-ticket lookup.
func (s *SyncService) SetWorkItemFindingLister(l WorkItemFindingLister) { s.workItems = l }

// SetRefusalCommentGuard wires refusal-comment deduplication (all replicas).
func (s *SyncService) SetRefusalCommentGuard(g RefusalCommentGuard) { s.refusalGuard = g }

// FixAppliedHook is called when a Jira webhook transitions a finding
// into the fix_applied state. Typical implementation: enqueue a
// verification scan on the finding's asset. Wired via
// SetPostFixAppliedHook; nil → no action (legacy behaviour).
//
// Implementations MUST be idempotent — the B3 rate-limiting guard in
// the implementation layer decides whether to actually enqueue a scan
// (e.g. max one per finding per 24h).
type FixAppliedHook func(ctx context.Context, tenantID, findingID shared.ID) error

// NewSyncService creates a new SyncService.
func NewSyncService(findingRepo vulnerability.FindingRepository, jiraClient Client, log *logger.Logger) *SyncService {
	return &SyncService{
		findingRepo: findingRepo,
		jiraClient:  jiraClient,
		logger:      log.With("service", "jira-sync"),
	}
}

// SetPostFixAppliedHook wires the verification-scan trigger. Safe to
// call after construction; nil value disables the hook.
func (s *SyncService) SetPostFixAppliedHook(h FixAppliedHook) {
	s.postFixHook = h
}

// SetCampaignSink wires the inbound epic→campaign sync. Safe to call after
// construction; nil disables it.
func (s *SyncService) SetCampaignSink(sink CampaignEpicSink) {
	s.campaignSink = sink
}

// SetClientResolver wires the per-tenant Jira client resolver. Safe to call
// after construction. Once set, CreateTicketFromFinding resolves a client from
// the tenant's integration instead of relying on the static client.
func (s *SyncService) SetClientResolver(r ClientResolver) {
	s.clientResolver = r
}

// SetMappingResolver wires the per-tenant mapping resolver for outbound status
// sync. Safe to call after construction; nil disables outbound sync.
func (s *SyncService) SetMappingResolver(r MappingResolver) {
	s.mappingResolver = r
}

// AssetRouteResolver supplies a finding's asset-level routing attributes so
// routing rules can match on them. Optional: when nil, routing matches only on
// finding-level fields (severity, tags). Implemented in infra by loading the
// asset (+ its group memberships).
type AssetRouteResolver interface {
	ResolveAssetRoute(ctx context.Context, tenantID, assetID shared.ID) (scope, criticality string, groups []string, err error)
}

// AssetNameResolver names a finding's asset (read in the finding's tenant)
// for the ticket summary's target. The wired AssetRouteResolver may also
// implement it; without it the summary names no asset.
type AssetNameResolver interface {
	AssetName(ctx context.Context, tenantID, assetID shared.ID) (string, error)
}

// findingAssetName is the name of f's asset, or "" when it cannot be read.
func (s *SyncService) findingAssetName(ctx context.Context, tenantID shared.ID, f *vulnerability.Finding) string {
	n, ok := s.assetRouteResolver.(AssetNameResolver)
	if !ok || f.AssetID().IsZero() {
		return ""
	}
	name, err := n.AssetName(ctx, tenantID, f.AssetID())
	if err != nil {
		return ""
	}
	return name
}

// SetAssetRouteResolver wires the optional asset-context resolver used by
// routing rules. Safe to call after construction.
func (s *SyncService) SetAssetRouteResolver(r AssetRouteResolver) {
	s.assetRouteResolver = r
}

// routeContext builds the RouteContext for a finding. Severity + tags are
// always available; asset scope/criticality/groups are filled in when an
// AssetRouteResolver is wired and the lookup succeeds. The lookup is
// best-effort — a routing context failure must never block ticket creation.
func (s *SyncService) routeContext(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding) RouteContext {
	rc := RouteContext{
		Severity: string(finding.Severity()),
		Tags:     finding.Tags(),
	}
	if s.assetRouteResolver != nil && !finding.AssetID().IsZero() {
		scope, criticality, groups, err := s.assetRouteResolver.ResolveAssetRoute(ctx, tenantID, finding.AssetID())
		if err != nil {
			s.logger.Debug("routing: asset context lookup failed; matching on finding fields only",
				"finding_id", finding.ID().String(), "error", err)
		} else {
			rc.Scope, rc.Criticality, rc.Groups = scope, criticality, groups
		}
	}
	return rc
}

// SyncFindingStatus is the async entrypoint for outbound status sync: it
// resolves the tenant's mapping then pushes the finding's status to its linked
// Jira issue. No-op when no mapping resolver is wired or the tenant has no Jira
// integration. Called by the jira-sync asynq handler.
func (s *SyncService) SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error {
	if s.mappingResolver == nil {
		return nil
	}
	// The mapping of the integration that owns the finding's issue.
	integrationID, _, err := s.findingIssueByID(ctx, tenantID, findingID)
	if err != nil {
		return err
	}
	mapping, err := s.mappingFor(ctx, tenantID, integrationID)
	if err != nil {
		if errors.Is(err, ErrNoTicketingIntegration) {
			return nil // tenant has no Jira integration — nothing to sync
		}
		return err
	}
	return s.SyncFindingStatusToTicket(ctx, tenantID, findingID, mapping)
}

// CommentOnFinding adds a comment to the Jira issue linked to a finding (RFC-039:
// a retest or a scan found the issue fixed, or saw it again). Outbound writes
// are opt-in per integration, exactly like status sync: a no-op unless the
// tenant's mapping has SyncEnabled, and when the finding has no linked issue.
// The body is platform-written text around values a sensor controls (the
// finding title, a retest reason, the tool name), so it is encoded here for
// every caller: each paragraph is one line of escaped wiki markup with its
// URLs defanged (jiraCommentBody).
func (s *SyncService) CommentOnFinding(ctx context.Context, tenantID, findingID shared.ID, body string) error {
	if s.mappingResolver == nil {
		return nil
	}
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}
	integrationID, issueKey, err := s.findingIssue(ctx, tenantID, finding)
	if err != nil {
		return err
	}
	if issueKey == "" {
		return nil
	}
	mapping, err := s.mappingFor(ctx, tenantID, integrationID)
	if err != nil {
		if errors.Is(err, ErrNoTicketingIntegration) {
			return nil
		}
		return err
	}
	if !mapping.SyncEnabled {
		return nil
	}
	// Gate the finding already read: a second read that failed would let
	// the comment out ungated.
	if ok, err := s.egressAllowed(ctx, tenantID, ticketing.RouteStatusSync, finding); !ok {
		return err
	}
	client, err := s.clientFor(ctx, tenantID, integrationID)
	if err != nil {
		return err
	}
	if err := client.AddComment(ctx, issueKey, jiraCommentBody(body)); err != nil {
		return fmt.Errorf("comment on jira issue: %w", err)
	}
	return nil
}

// resolveClient returns the Jira client to use for a tenant. A statically
// injected client (tests) wins; otherwise the resolver loads the tenant's
// integration. Returns ErrNoTicketingIntegration when neither is available.
func (s *SyncService) resolveClient(ctx context.Context, tenantID shared.ID) (Client, error) {
	if s.jiraClient != nil {
		return s.jiraClient, nil
	}
	if s.clientResolver != nil {
		return s.clientResolver.Resolve(ctx, tenantID)
	}
	return nil, ErrNoTicketingIntegration
}

// findingIssueByID loads a finding and returns its issue (see findingIssue).
func (s *SyncService) findingIssueByID(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, string, error) {
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return shared.ID{}, "", fmt.Errorf("get finding: %w", err)
	}
	return s.findingIssue(ctx, tenantID, finding)
}

// findingIssue returns a finding's issue and the integration that owns it:
// its active link (the integration is on the link), else a browse URL from
// its ticket list on the default integration's site (the zero id names the
// default integration). A URL on another site names no issue of the default
// integration, so it is never pushed through it. "" when the finding has no
// issue.
func (s *SyncService) findingIssue(ctx context.Context, tenantID shared.ID, finding *vulnerability.Finding) (shared.ID, string, error) {
	if s.links != nil {
		links, err := s.links.ListForFinding(ctx, tenantID, finding.ID())
		if err != nil {
			return shared.ID{}, "", fmt.Errorf("list the finding's ticket links: %w", err)
		}
		for _, l := range links {
			if l.State == ticketlink.StateActive && l.Provider == "jira" {
				return l.IntegrationID, l.ExternalKey, nil
			}
		}
	}
	site := ""
	if s.mappingResolver != nil {
		if m, err := s.mappingResolver.ResolveMapping(ctx, tenantID); err == nil {
			site = strings.ToLower(strings.TrimRight(m.SiteURL, "/"))
		}
	}
	for _, u := range finding.WorkItemURIs() {
		m := jiraBrowseKeyRe.FindStringSubmatch(u)
		if m == nil {
			continue
		}
		if site != "" && !strings.HasPrefix(strings.ToLower(u), site+"/browse/") {
			continue
		}
		return shared.ID{}, m[1], nil
	}
	return shared.ID{}, "", nil
}

// clientFor returns the client of one integration of the tenant; a zero id
// means the tenant's default integration (a create that names none). It
// never falls back to another integration: a link or a delivery of
// integration B is never served by integration A's client.
func (s *SyncService) clientFor(ctx context.Context, tenantID, integrationID shared.ID) (Client, error) {
	if integrationID.IsZero() {
		return s.resolveClient(ctx, tenantID)
	}
	if s.jiraClient != nil {
		// A statically injected client (tests) serves one integration only.
		if ii, ok := s.jiraClient.(IssueIdentifier); ok && ii.IntegrationID() != integrationID {
			return nil, ErrNoTicketingIntegration
		}
		return s.jiraClient, nil
	}
	if s.clientResolver != nil {
		return s.clientResolver.ResolveByID(ctx, tenantID, integrationID)
	}
	return nil, ErrNoTicketingIntegration
}

// mappingFor loads the mapping of one integration of the tenant (a zero id:
// the default integration). With no resolver wired (tests) it is the
// default mapping on the static client's site.
func (s *SyncService) mappingFor(ctx context.Context, tenantID, integrationID shared.ID) (MappingConfig, error) {
	if s.mappingResolver == nil {
		m := DefaultMappingConfig()
		if sc, ok := s.jiraClient.(interface{ SiteURL() string }); ok {
			m.SiteURL = sc.SiteURL()
		}
		return m, nil
	}
	if integrationID.IsZero() {
		return s.mappingResolver.ResolveMapping(ctx, tenantID)
	}
	return s.mappingResolver.ResolveMappingByID(ctx, tenantID, integrationID)
}

// ListProjects returns the Jira projects visible to the tenant's connected
// ticketing integration, for the admin project picker. Returns
// ErrNoTicketingIntegration when the tenant has no connected Jira integration.
func (s *SyncService) ListProjects(ctx context.Context, tenantID shared.ID) ([]ProjectRef, error) {
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return client.ListProjects(ctx)
}

// CreateTicketInput is the payload for auto-creating a Jira ticket from a finding.
type CreateTicketInput struct {
	TenantID   string `json:"tenant_id"`
	FindingID  string `json:"finding_id"`
	ProjectKey string `json:"project_key"` // e.g. "SEC"
	IssueType  string `json:"issue_type"`  // e.g. "Bug"
	// ParentKey creates the ticket as a child of this issue (an epic).
	ParentKey string `json:"parent_key,omitempty"`
	// IntegrationID names the Jira integration to create the issue on; ""
	// means the tenant's default integration.
	IntegrationID string `json:"integration_id,omitempty"`
	// Route is the path the request came by, set by the server's callers
	// only (never decoded from a request); the zero value is the generic
	// finding route.
	Route ticketing.Route `json:"-"`
}

// jiraBrowseKeyRe extracts a Jira issue key from a browse URL,
// e.g. "https://org.atlassian.net/browse/SEC-123" → "SEC-123".
var jiraBrowseKeyRe = regexp.MustCompile(`/browse/([A-Z][A-Z0-9_]+-\d+)`)

// firstJiraIssueKey returns the first Jira issue key found among a finding's
// work-item URIs, or "" if none is a Jira browse URL.
func firstJiraIssueKey(uris []string) string {
	for _, u := range uris {
		if m := jiraBrowseKeyRe.FindStringSubmatch(u); m != nil {
			return m[1]
		}
	}
	return ""
}

// SyncFindingStatusToTicket pushes a finding's status to its linked Jira issue
// (the outbound half of bidirectional sync — RFC-006 Phase 3). It is a no-op
// unless the integration opted in (mapping.SyncEnabled) and the finding status
// maps to a target Jira status. Echo-safe: it only acts on the OpenCTEM-initiated
// status-change path (the inbound webhook updates findings directly, bypassing
// this), and additionally skips when the issue is already at the target.
//
// On a workflow with no transition to the target, it falls back to a comment so
// the change is visible to a human rather than failing.
func (s *SyncService) SyncFindingStatusToTicket(ctx context.Context, tenantID, findingID shared.ID, mapping MappingConfig) error {
	if ok, err := s.statusPushAllowed(ctx, tenantID, findingID); !ok {
		return err
	}
	// A published mapping profile for the issue's project decides the move
	// itself (its status map is the explicit opt-in for that destination).
	if s.profiles != nil {
		if handled, err := s.syncWithProfile(ctx, tenantID, findingID); handled {
			return err
		}
	}
	if !mapping.SyncEnabled {
		return nil // outbound sync is opt-in per integration (default off)
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("get finding: %w", err)
	}

	target, ok := mapping.JiraStatusForFinding(string(finding.Status()))
	if !ok {
		return nil // this finding status intentionally does not move the ticket
	}

	integrationID, issueKey, err := s.findingIssue(ctx, tenantID, finding)
	if err != nil {
		return err
	}
	if issueKey == "" {
		return nil // finding isn't linked to a Jira issue
	}

	client, err := s.clientFor(ctx, tenantID, integrationID)
	if err != nil {
		return err
	}

	// Echo-guard / idempotency: if Jira is already at the target, do nothing.
	if cur, err := client.GetIssueStatus(ctx, issueKey); err == nil && strings.EqualFold(cur, target) {
		return nil
	}

	comment := fmt.Sprintf("%s set this finding to %q.", brand.Name(), finding.Status())
	if err := client.TransitionToStatus(ctx, issueKey, target, comment); err != nil {
		if errors.Is(err, ErrNoMatchingTransition) {
			// Workflow can't reach the target from its current status — leave a
			// note instead of failing so a human can move the card.
			body := fmt.Sprintf("%s marked this finding %q, but no Jira transition to %q is available from its current status — please move it manually.", brand.Name(),
				finding.Status(), target)
			if cErr := client.AddComment(ctx, issueKey, body); cErr != nil {
				return fmt.Errorf("comment fallback after no transition: %w", cErr)
			}
			s.logger.Info("jira outbound: no transition to target, commented instead",
				"finding_id", findingID.String(), "issue_key", issueKey, "target", target)
			return nil
		}
		return fmt.Errorf("transition jira issue: %w", err)
	}

	s.logger.Info("jira outbound: synced finding status to ticket",
		"finding_id", findingID.String(), "issue_key", issueKey,
		"finding_status", finding.Status(), "jira_status", target)
	return nil
}

// CreateTicketFromFinding auto-creates a Jira ticket from a finding and links it.
func (s *SyncService) CreateTicketFromFinding(ctx context.Context, input CreateTicketInput) (*TicketInfo, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding ID", shared.ErrValidation)
	}

	var integrationID shared.ID
	if v := strings.TrimSpace(input.IntegrationID); v != "" {
		if integrationID, err = shared.IDFromString(v); err != nil {
			return nil, fmt.Errorf("%w: invalid integration ID", shared.ErrValidation)
		}
	}

	// The chosen integration's client; its ticketing config drives the
	// destination project, issue type and severity→priority mapping.
	jiraClient, err := s.clientFor(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if ii, ok := jiraClient.(IssueIdentifier); ok {
		integrationID = ii.IntegrationID()
	}
	mapping, err := s.mappingFor(ctx, tenantID, integrationID)
	if err != nil {
		mapping = DefaultMappingConfig()
	}

	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if err := s.egress.Check(ctx, tenantID, input.Route, finding); err != nil {
		return nil, err
	}

	// Destination project resolution, in priority order:
	//   1. explicit request project_key (caller knows best),
	//   2. a matching routing rule (route by team/severity/asset attributes),
	//   3. the tenant's default project,
	//   4. else a validation error — we never guess where a ticket goes.
	// A routing rule may also override the issue type for that route.
	projectKey := strings.TrimSpace(input.ProjectKey)
	routeIssueType := ""
	if projectKey == "" {
		if rule, ok := mapping.RouteFor(s.routeContext(ctx, tenantID, finding)); ok {
			projectKey = rule.ProjectKey
			routeIssueType = rule.IssueType
		}
	}
	if projectKey == "" {
		projectKey = mapping.DefaultProjectKey
	}
	if projectKey == "" {
		return nil, fmt.Errorf("%w: project_key is required (no routing match and no default project configured)", shared.ErrValidation)
	}

	// Idempotency: if this finding already has a ticket in the target project,
	// return it instead of creating a duplicate. Without this, a re-scan,
	// workflow re-trigger, or retry that calls CreateTicketFromFinding again
	// would open a second Jira issue for the same finding. Jira browse URLs are
	// ".../browse/<PROJECT>-<n>", so an existing work-item URL containing
	// "/browse/<ProjectKey>-" means this finding is already ticketed here.
	// Compare case-insensitively: Jira browse URLs use the upper-case project
	// key even if the integration was configured with a lower-case key, and
	// without this the check would miss and a duplicate ticket would be created.
	browseMarker := strings.ToUpper("/browse/" + projectKey + "-")
	for _, uri := range finding.WorkItemURIs() {
		if strings.Contains(strings.ToUpper(uri), browseMarker) {
			// Prefer the canonical key via the shared regex (robust to trailing
			// slashes / query strings); fall back to the trailing path segment.
			key := uri[strings.LastIndex(uri, "/")+1:]
			if m := jiraBrowseKeyRe.FindStringSubmatch(uri); m != nil {
				key = m[1]
			}
			s.logger.Info("jira ticket already exists for finding; skipping create",
				"finding_id", findingID.String(), "ticket_key", key, "project", projectKey)
			return &TicketInfo{
				FindingID: findingID.String(),
				TicketKey: key,
				TicketURL: uri,
				LinkedAt:  time.Now().UTC(),
			}, nil
		}
	}

	// Map finding severity to Jira priority via the tenant's mapping (defaults
	// reproduce the original critical→Highest … low→Low table).
	priority := mapping.PriorityForSeverity(string(finding.Severity()))

	// Issue type: explicit request wins, else the matched route's override,
	// else the integration's finding type (by id in its default project).
	issueType := IssueTypeRef{Name: strings.TrimSpace(input.IssueType)}
	if issueType.Name == "" {
		issueType.Name = routeIssueType
	}
	if issueType.Name == "" {
		issueType = mapping.IssueTypeFor(IssueKindFinding, projectKey)
	}

	// A previous attempt may have created the issue and lost the response
	// or failed to record it: adopt that issue instead of creating another.
	marker := markerFor(jiraClient, MarkerKindFinding, findingID)
	result, err := s.findMarked(ctx, jiraClient, marker, func(key string) bool {
		return strings.EqualFold(ticketlink.ProjectOf(key), projectKey)
	})
	if err != nil {
		return nil, err
	}
	handled := result != nil
	if !handled {
		result, handled, err = s.createFromProfile(ctx, jiraClient, tenantID, ticketmap.ObjectFinding, findingID, projectKey, issueType.Lookup(), strings.TrimSpace(input.ParentKey), marker)
		if err != nil {
			return nil, err
		}
	}
	if !handled {
		result, err = jiraClient.CreateIssue(ctx, CreateIssueInput{
			ProjectKey:  projectKey,
			Summary:     ticketSummary(finding, s.findingAssetName(ctx, tenantID, finding)),
			Description: ticketDescription(finding),
			IssueType:   issueType.Name,
			IssueTypeID: issueType.ID,
			Priority:    priority,
			Labels:      []string{"openctem", "security", string(finding.Severity())},
			ParentKey:   strings.TrimSpace(input.ParentKey),
			Marker:      marker,
		})
		s.noteCreate(ctx, tenantID, integrationID, IssueKindFinding, issueType, err)
		if err != nil {
			return nil, fmt.Errorf("create jira ticket: %w", err)
		}
	}

	s.recordCreatedLink(ctx, jiraClient, tenantID, findingID, result, strings.TrimSpace(input.ParentKey))

	// Auto-link the created ticket to the finding
	finding.AddWorkItemURI(result.BrowseURL)
	if err := s.findingRepo.UpdateWorkItemURIs(ctx, tenantID, findingID, finding.WorkItemURIs()); err != nil {
		s.logger.Error("failed to link created ticket to finding", "error", err, "ticket_key", result.Key)
	}

	s.logger.Info("jira ticket created from finding",
		"finding_id", findingID.String(),
		"ticket_key", result.Key,
		"ticket_url", result.BrowseURL,
	)

	return &TicketInfo{
		FindingID: findingID.String(),
		TicketKey: result.Key,
		TicketURL: result.BrowseURL,
		LinkedAt:  time.Now().UTC(),
	}, nil
}

// syncWithProfile loads the finding's linked issue and lets a published
// profile move it. handled is false when there is no profile to apply.
func (s *SyncService) syncWithProfile(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	finding, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return false, nil //nolint:nilerr // the built-in path reports the lookup error
	}
	integrationID, issueKey, err := s.findingIssue(ctx, tenantID, finding)
	if err != nil || issueKey == "" {
		return false, nil //nolint:nilerr // the built-in path reports the lookup error
	}
	client, err := s.clientFor(ctx, tenantID, integrationID)
	if err != nil {
		return false, nil //nolint:nilerr // the built-in path reports a missing integration
	}
	return s.syncStatusFromProfile(ctx, client, tenantID, findingID, issueKey)
}

// CreateEpic creates a Jira epic for the given tenant and returns its key and
// browse URL. It is provider-plumbing only — campaign-agnostic — so the
// remediation campaign service can own the "campaign -> epic" orchestration
// (idempotency + persistence) without coupling the jira package to the
// remediation domain. Summary/description are secret-redacted defensively. The
// signature uses primitives so callers can depend on a narrow interface without
// importing the jira package.
func (s *SyncService) CreateEpic(ctx context.Context, tenantID shared.ID, projectKey, summary, description string, labels []string) (issueKey, issueURL string, err error) {
	if projectKey == "" {
		return "", "", fmt.Errorf("%w: project_key is required", shared.ErrValidation)
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return "", "", err
	}
	// The integration's epic type (a custom one included), else Epic.
	issueType := IssueTypeRef{Name: stockIssueTypes[IssueKindEpic]}
	var integrationID shared.ID
	if ii, ok := client.(IssueIdentifier); ok {
		integrationID = ii.IntegrationID()
		if mapping, merr := s.mappingFor(ctx, tenantID, integrationID); merr == nil {
			issueType = mapping.IssueTypeFor(IssueKindEpic, projectKey)
		}
	}
	result, err := client.CreateIssue(ctx, CreateIssueInput{
		ProjectKey:  projectKey,
		Summary:     safetext.SingleLine(safetext.RedactSecrets(summary), safetext.MaxTitleRunes),
		Description: safetext.JiraWikiBlock(safetext.RedactSecrets(description), safetext.MaxDescriptionRunes),
		IssueType:   issueType.Name,
		IssueTypeID: issueType.ID,
		Labels:      labels,
	})
	s.noteCreate(ctx, tenantID, integrationID, IssueKindEpic, issueType, err)
	if err != nil {
		return "", "", fmt.Errorf("create jira epic: %w", err)
	}
	s.logger.Info("jira epic created", "tenant_id", tenantID.String(), "issue_key", result.Key, "project", projectKey)
	return result.Key, result.BrowseURL, nil
}

// TransitionEpic moves a campaign's linked Jira epic to a target status NAME,
// best-effort and echo-safe: it skips when the epic is already at the target,
// and falls back to a comment when the workflow offers no transition (so the
// change is visible to a human rather than failing). Campaign-agnostic plumbing
// — the caller decides when/where to call it.
func (s *SyncService) TransitionEpic(ctx context.Context, tenantID shared.ID, issueKey, targetStatus, comment string) error {
	if issueKey == "" || targetStatus == "" {
		return nil
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return err
	}

	// Echo-guard: already at the target -> nothing to do.
	if cur, gerr := client.GetIssueStatus(ctx, issueKey); gerr == nil && strings.EqualFold(cur, targetStatus) {
		return nil
	}

	if terr := client.TransitionToStatus(ctx, issueKey, targetStatus, comment); terr != nil {
		if errors.Is(terr, ErrNoMatchingTransition) {
			body := fmt.Sprintf("%s wanted to move this epic to %q but no transition is available from its current status — please move it manually.", brand.Name(), targetStatus)
			if cerr := client.AddComment(ctx, issueKey, body); cerr != nil {
				return fmt.Errorf("comment fallback after no transition: %w", cerr)
			}
			s.logger.Info("jira epic outbound: no transition to target, commented instead", "issue_key", issueKey, "target", targetStatus)
			return nil
		}
		return fmt.Errorf("transition jira epic: %w", terr)
	}
	s.logger.Info("jira epic outbound: synced campaign status to epic", "issue_key", issueKey, "target", targetStatus)
	return nil
}

// WebhookPayload is the envelope sent by Jira issue-updated webhooks.
// See https://developer.atlassian.com/cloud/jira/platform/webhooks/
type WebhookPayload struct {
	WebhookEvent string `json:"webhookEvent"` // "jira:issue_updated"
	// Timestamp is when Jira created the event, in milliseconds since the
	// epoch (the inbound route refuses an old delivery).
	Timestamp int64 `json:"timestamp"`
	// User is the Jira account that made the change (accountId on Cloud,
	// name/key on Data Center), recorded on every finding it moves.
	User      WebhookUser  `json:"user"`
	Issue     WebhookIssue `json:"issue"`
	Changelog *Changelog   `json:"changelog,omitempty"`
}

// WebhookUser is the actor block of a Jira webhook payload.
type WebhookUser struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	Key       string `json:"key"`
}

// ID is the account identifier to record: accountId, else name, else key,
// cleaned and capped.
func (u WebhookUser) ID() string {
	id := u.AccountID
	if id == "" {
		id = u.Name
	}
	if id == "" {
		id = u.Key
	}
	return safetext.SingleLine(id, 128)
}

// WebhookIssue represents the issue block inside a Jira webhook payload.
type WebhookIssue struct {
	// ID is the issue's id ("10001"), stable when the issue moves to another
	// project and its key changes.
	ID     string                 `json:"id"`
	Key    string                 `json:"key"`  // e.g. "PROJ-123"
	Self   string                 `json:"self"` // e.g. "https://myorg.atlassian.net/rest/api/2/issue/10001"
	Fields map[string]interface{} `json:"fields"`
}

// Changelog carries the before/after values of changed fields.
type Changelog struct {
	Items []ChangeItem `json:"items"`
}

// ChangeItem is one entry in the changelog.
type ChangeItem struct {
	Field      string `json:"field"`
	From       string `json:"from"` // the status id for a status change
	To         string `json:"to"`
	FromString string `json:"fromString"`
	ToString   string `json:"toString"`
}

// inboundRef names where an inbound delivery came from: the tenant, the
// integration whose own secret signed it, and that integration's mapping
// (with its site). Every lookup and every comment of the delivery stays on
// that integration.
type inboundRef struct {
	tenantID      shared.ID
	integrationID shared.ID
	mapping       MappingConfig
}

// ErrInboundNoIntegration: an inbound delivery must name the integration
// that signed it.
var ErrInboundNoIntegration = fmt.Errorf("%w: an inbound delivery names its integration", shared.ErrValidation)

// HandleJiraWebhook processes an inbound Jira webhook of one integration and
// syncs finding status. integrationID is the integration the delivery was
// verified for (its URL and its secret): issues and links are matched within
// that integration only, by the issue's id first and its key second, so a
// tenant with two Jira sites never moves site A's links from a delivery of
// site B even when both have an issue SEC-1.
//
// Status mapping:
//
//	Jira "In Progress"  → finding "in_progress"
//	Jira "In Review"    → finding "in_progress"
//	Jira "Done"         → finding "fix_applied"  (triggers verification flow)
//	Jira "Resolved"     → finding "fix_applied"
//	Jira "Closed"       → finding "fix_applied"
func (s *SyncService) HandleJiraWebhook(ctx context.Context, tenantID, integrationID shared.ID, payload WebhookPayload) error {
	if integrationID.IsZero() {
		return ErrInboundNoIntegration
	}
	if payload.Changelog == nil {
		// No changes — nothing to sync.
		return nil
	}

	// Find the status transition in the changelog.
	newJiraStatus := ""
	for _, item := range payload.Changelog.Items {
		if strings.EqualFold(item.Field, "status") {
			newJiraStatus = item.ToString
			break
		}
	}
	if newJiraStatus == "" {
		// Webhook is for a non-status change (field update, comment, etc.) — ignore.
		return nil
	}

	mapping, err := s.mappingFor(ctx, tenantID, integrationID)
	if err != nil {
		if errors.Is(err, ErrNoTicketingIntegration) {
			s.logger.Warn("jira webhook: the integration is gone; ignored", "integration_id", integrationID.String())
			return nil
		}
		return fmt.Errorf("load the integration's mapping: %w", err)
	}
	in := inboundRef{tenantID: tenantID, integrationID: integrationID, mapping: mapping}

	// A campaign's epic: the campaign service decides (Done claims the fix
	// of the campaign's findings; it never completes the campaign). Only an
	// epic on this integration's site matches.
	if s.campaignSink != nil {
		refusals, handled, cerr := s.campaignSink.HandleEpicStatusChange(ctx, tenantID, mapping.SiteURL, payload.Issue.Key, newJiraStatus, payload.User.ID())
		if cerr != nil {
			s.logger.Warn("jira webhook: inbound campaign epic sync failed",
				"issue_key", logger.SanitizeValue(payload.Issue.Key), "error", cerr)
		}
		if handled {
			s.commentRefusals(ctx, in, payload.Issue.Key, newJiraStatus, refusals)
			return nil
		}
	}

	// Only issues in projects configured for ticketing move findings.
	if ok, err := s.inboundProjectAllowed(ctx, in, payload.Issue.Key); err != nil {
		return fmt.Errorf("check the issue's project: %w", err)
	} else if !ok {
		s.logger.Warn("jira webhook: issue outside the projects configured for ticketing; ignored",
			"issue_key", logger.SanitizeValue(payload.Issue.Key))
		return nil
	}

	// A published mapping profile for the issue's project decides what the
	// status means (an intent); without one the built-in map applies.
	if handled, err := s.handleProfileIntent(ctx, in, payload, newJiraStatus); handled {
		return err
	}

	newFindingStatus, ok := in.inboundMapping().FindingStatusForJira(newJiraStatus)
	if !ok {
		s.logger.Debug("jira status has no finding mapping — ignored",
			"jira_status", logger.SanitizeValue(newJiraStatus),
			"issue_key", logger.SanitizeValue(payload.Issue.Key),
		)
		return nil
	}
	return s.applyToLinked(ctx, in, payload, newJiraStatus, newFindingStatus)
}

// applyToLinked applies a work-state status to every finding linked to the
// issue through the finding service, queues the verification of a fix claim
// and comments the refusals back.
func (s *SyncService) applyToLinked(ctx context.Context, in inboundRef, payload WebhookPayload, newJiraStatus string, newFindingStatus vulnerability.FindingStatus) error {
	tenantID := in.tenantID
	// Whatever the mapping says, a ticket never closes a finding (no verify
	// gate, no approval, no person). FindingStatusForJira already refuses
	// these; this keeps the rule if the mapping code changes.
	if !newFindingStatus.IsTicketInboundTarget() {
		s.logger.Warn("jira webhook: refused a closing status from a ticket",
			"issue_key", logger.SanitizeValue(payload.Issue.Key), "target_status", logger.SanitizeValue(string(newFindingStatus)))
		return nil
	}

	ids, err := s.linkedFindingsOf(ctx, in, payload, newJiraStatus)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		s.logger.Debug("no finding linked to jira ticket", "issue_key", logger.SanitizeValue(payload.Issue.Key))
		return nil
	}
	if s.applier == nil {
		// Fail closed: without the service path nothing is applied.
		s.logger.Error("jira webhook: inbound status applier not wired; change not applied",
			"issue_key", logger.SanitizeValue(payload.Issue.Key))
		return nil
	}

	applied, refused, err := s.applier.ApplyTicketStatus(ctx, tenantID, ids, newFindingStatus, "jira", payload.Issue.Key, payload.User.ID())
	if err != nil {
		return fmt.Errorf("apply jira status to linked findings: %w", err)
	}
	s.logger.Info("jira webhook applied ticket status",
		"issue_key", logger.SanitizeValue(payload.Issue.Key),
		"finding_status", newFindingStatus, "linked", len(ids), "applied", len(applied), "refused", len(refused))

	// A fix claim also asks for a verification scan of each claimed finding.
	// Hook errors are logged, never returned: Jira retries on non-2xx.
	if newFindingStatus == vulnerability.FindingStatusFixApplied && s.postFixHook != nil {
		for _, id := range applied {
			if err := s.postFixHook(ctx, tenantID, id); err != nil {
				s.logger.Warn("post-fix hook failed; finding status still updated", "finding_id", id.String(), "error", err)
			}
		}
	}

	lines := make([]string, 0, len(refused))
	for _, r := range refused {
		lines = append(lines, r.FindingID+": "+r.Reason)
	}
	s.commentRefusals(ctx, in, payload.Issue.Key, newJiraStatus, lines)
	return nil
}

// linkedFindings returns every finding of the tenant linked to the ticket URL.
func (s *SyncService) linkedFindings(ctx context.Context, tenantID shared.ID, ticketURL string) ([]shared.ID, error) {
	if s.workItems != nil {
		ids, err := s.workItems.ListIDsByWorkItemURI(ctx, tenantID, ticketURL, maxInboundFindings)
		if err != nil {
			return nil, fmt.Errorf("lookup findings by work item URI: %w", err)
		}
		return ids, nil
	}
	f, err := s.findingRepo.GetByWorkItemURI(ctx, tenantID, ticketURL)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup finding by work item URI: %w", err)
	}
	return []shared.ID{f.ID()}, nil
}

// commentRefusals tells the people working the ticket which findings the
// change did not move and why: one comment, not repeated for the same issue,
// status and reasons within refusalCommentWindow. Best effort.
func (s *SyncService) commentRefusals(ctx context.Context, in inboundRef, issueKey, jiraStatus string, refusals []string) {
	if len(refusals) == 0 {
		return
	}
	shown := refusals
	if len(shown) > maxRefusalLines {
		shown = shown[:maxRefusalLines]
	}
	body := fmt.Sprintf("OpenCTEM did not apply the status %q to %d linked finding(s). Findings are verified in OpenCTEM (a retest, a covered scan or a reviewer), never closed from a ticket.\n\n%s",
		jiraStatus, len(refusals), strings.Join(shown, "\n\n"))
	if len(refusals) > len(shown) {
		body += fmt.Sprintf("\n\n(and %d more)", len(refusals)-len(shown))
	}
	s.commentOnce(ctx, in, issueKey, jiraStatus, body)
}

// commentOnce posts a comment on the issue once per issue, status and body
// within refusalCommentWindow (all replicas), so a retried or repeated
// delivery comments once. The comment goes to the delivery's own
// integration. Best effort.
func (s *SyncService) commentOnce(ctx context.Context, in inboundRef, issueKey, jiraStatus, body string) {
	tenantID := in.tenantID
	sum := sha256.Sum256([]byte(body))
	key := "jira-refusal:" + tenantID.String() + ":" + in.integrationID.String() + ":" + issueKey + ":" + jiraStatus + ":" + hex.EncodeToString(sum[:8])
	if s.refusalGuard != nil {
		first, err := s.refusalGuard.FirstDelivery(ctx, key, refusalCommentWindow)
		if err != nil || !first {
			return
		}
	}
	client, err := s.clientFor(ctx, tenantID, in.integrationID)
	if err != nil {
		s.logger.Warn("jira comment: no client", "tenant_id", tenantID.String(), "integration_id", in.integrationID.String(), "error", err)
		return
	}
	if err := client.AddComment(ctx, issueKey, jiraCommentBody(body)); err != nil {
		s.logger.Warn("jira comment failed", "issue_key", logger.SanitizeValue(issueKey), "error", err)
	}
}

// inboundMapping is the delivery's inbound status map: its integration's
// overlay when it has one, the defaults otherwise. Either way
// FindingStatusForJira only ever yields IsTicketInboundTarget statuses.
func (in inboundRef) inboundMapping() MappingConfig {
	if in.mapping.StatusInbound != nil {
		return in.mapping
	}
	return DefaultMappingConfig()
}

// StatusActivityRecorder records a status change whose actor is an
// integration (a ticket webhook), naming the integration and the ticket.
type StatusActivityRecorder interface {
	RecordIntegrationStatusChange(ctx context.Context, tenantID, findingID shared.ID, oldStatus, newStatus, integration, ref string) error
}

// SetActivityRecorder wires the finding-activity recorder for inbound changes.
func (s *SyncService) SetActivityRecorder(r StatusActivityRecorder) { s.activity = r }

// TicketInfo is returned by LinkTicket to the HTTP handler for the response body.
type TicketInfo struct {
	FindingID string    `json:"finding_id"`
	TicketKey string    `json:"ticket_key"`
	TicketURL string    `json:"ticket_url"`
	LinkedAt  time.Time `json:"linked_at"`
}

// jiraCommentBody encodes a comment for Jira wiki markup: paragraphs (split on
// blank lines) stay paragraphs, each folded to one line, escaped and with its
// URLs defanged, so a finding title such as "[x|https://evil.test] !img! [~admin]"
// renders as text: no link, no image beacon, no mention.
func jiraCommentBody(body string) string {
	paras := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n\n")
	out := make([]string, 0, len(paras))
	for _, p := range paras {
		if e := safetext.JiraWikiInline(p, safetext.MaxInlineRunes); e != "" {
			out = append(out, e)
		}
	}
	return strings.Join(out, "\n\n")
}

// IssueRef is a Jira issue as shown to an issue picker.
type IssueRef struct {
	Key     string `json:"key"`
	Summary string `json:"summary"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	URL     string `json:"url"`
}

// issueSearcher is implemented by clients that can search issues and name
// their site (the production client; test stubs need not).
type issueSearcher interface {
	SiteURL() string
	SearchIssues(ctx context.Context, text string, max int) ([]IssueRef, error)
}

// ErrIssueSearchUnsupported: the tenant's Jira client cannot search.
var ErrIssueSearchUnsupported = fmt.Errorf("%w: the Jira integration cannot search issues", shared.ErrValidation)

// SiteURL returns the tenant's connected Jira site (scheme and host), or
// ErrNoTicketingIntegration.
func (s *SyncService) SiteURL(ctx context.Context, tenantID shared.ID) (string, error) {
	c, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if is, ok := c.(issueSearcher); ok {
		return is.SiteURL(), nil
	}
	return "", ErrIssueSearchUnsupported
}

// SearchIssues searches the tenant's Jira for an issue picker (at most 20).
func (s *SyncService) SearchIssues(ctx context.Context, tenantID shared.ID, text string) ([]IssueRef, error) {
	c, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	is, ok := c.(issueSearcher)
	if !ok {
		return nil, ErrIssueSearchUnsupported
	}
	return is.SearchIssues(ctx, text, 20)
}
