package ticketing

// The outbound gate for tracker content (docs/architecture/ticketing-integration.md,
// "Outbound gate"). Every path that sends finding or task content to a
// tracker (Jira, GitHub Issues) asks this gate first: creating an issue for
// a finding or a task, the workflow ticket actions, the campaign's tickets
// and the status pushes on issues that already exist. One gate, so a rule
// added here holds on every path.
//
// What it decides:
//   - pentest findings leave only through the campaign route (the campaign
//     Lead's "tickets under the epic" action) and the status pushes of the
//     issues that route created; the generic finding route, task issues and
//     workflows are refused;
//   - a campaign's TLP must be within the organization's tracker limit
//     (pentest settings, default TLP:AMBER); TLP:RED never leaves, whatever
//     the limit;
//   - what text may leave for a finding (FindingContent): secret findings
//     send no preview, snippet, fingerprint or commit context; findings that
//     expose data send counts and locations only, no free text.

import (
	"context"
	"errors"
	"fmt"
	"slices"

	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Route is the path content takes to a tracker.
type Route string

const (
	// RouteFinding is a person's "create ticket" on one finding
	// (POST /findings/{id}/create-ticket). The zero value means this route,
	// the strictest create path.
	RouteFinding Route = ""
	// RouteCampaign is the campaign Lead's tickets under the campaign's epic.
	RouteCampaign Route = "campaign"
	// RouteAutomation is a workflow's create_ticket / update_ticket action.
	RouteAutomation Route = "automation"
	// RouteTask is a remediation task's issue.
	RouteTask Route = "task"
	// RouteStatusSync pushes a state change to an issue that already exists.
	RouteStatusSync Route = "status_sync"
)

// EgressReason is the stable code of a refusal.
type EgressReason string

const (
	// ReasonPentestCampaignOnly: a pentest finding outside the campaign route.
	ReasonPentestCampaignOnly EgressReason = "pentest_campaign_route_only"
	// ReasonPentestNoCampaign: a pentest finding whose campaign is missing
	// or cannot be checked.
	ReasonPentestNoCampaign EgressReason = "pentest_without_campaign"
	// ReasonTLPRed: TLP:RED content never goes to a tracker.
	ReasonTLPRed EgressReason = "tlp_red"
	// ReasonTLPAboveLimit: the campaign's TLP is above the organization's
	// tracker limit.
	ReasonTLPAboveLimit EgressReason = "tlp_above_tracker_limit"
)

// ErrEgressRefused matches every refusal of the gate (errors.Is). It wraps
// shared.ErrForbidden, so the HTTP layer answers 403.
var ErrEgressRefused = fmt.Errorf("%w: ticket_egress_refused", shared.ErrForbidden)

// EgressRefusedError is a refusal: the content stays on the platform.
type EgressRefusedError struct {
	Reason      EgressReason
	CampaignTLP pentestdom.TLP
	MaxTLP      pentestdom.TLP
}

func (e *EgressRefusedError) Error() string {
	switch e.Reason {
	case ReasonPentestCampaignOnly:
		return "pentest findings go to a tracker only from their campaign, by the campaign lead"
	case ReasonPentestNoCampaign:
		return "a pentest finding without a readable campaign is not sent to a tracker"
	case ReasonTLPRed:
		return "TLP:RED content is never sent to a tracker"
	case ReasonTLPAboveLimit:
		return fmt.Sprintf("the campaign is %s, above the organization's tracker limit %s", e.CampaignTLP.Label(), e.MaxTLP.Label())
	}
	return string(e.Reason)
}

// Is makes errors.Is(err, ErrEgressRefused) and errors.Is(err,
// shared.ErrForbidden) true.
func (e *EgressRefusedError) Is(target error) bool {
	return target == ErrEgressRefused || target == shared.ErrForbidden
}

// TrackerTLPLimit returns the organization's TLP limit for trackers ("" =
// the default, amber). A read error is returned so the gate fails closed.
type TrackerTLPLimit interface {
	TrackerMaxTLP(ctx context.Context, tenantID shared.ID) (string, error)
}

// EgressCampaigns reads a pentest campaign of the tenant.
type EgressCampaigns interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*pentestdom.Campaign, error)
}

// DefaultTrackerMaxTLP is the tracker limit when the organization set none.
const DefaultTrackerMaxTLP = pentestdom.TLPAmber

// EgressGate is the outbound gate. A nil gate, or one without a campaign
// reader, still refuses every pentest finding (nothing can be checked).
type EgressGate struct {
	limits    TrackerTLPLimit
	campaigns EgressCampaigns
}

// NewEgressGate builds the gate. A nil limit reader applies the default
// limit (amber).
func NewEgressGate(limits TrackerTLPLimit, campaigns EgressCampaigns) *EgressGate {
	return &EgressGate{limits: limits, campaigns: campaigns}
}

// IsPentest reports whether a finding is pentest content: its source, or a
// campaign reference (either one is enough).
func IsPentest(f *vulnerability.Finding) bool {
	return f != nil && (f.Source() == vulnerability.FindingSourcePentest || f.PentestCampaignID() != nil)
}

// maxTLP is the organization's tracker limit, never above amber+strict
// (TLP:RED is refused before the limit is read). An unknown stored value
// fails closed to clear.
func (g *EgressGate) maxTLP(ctx context.Context, tenantID shared.ID) (pentestdom.TLP, error) {
	if g == nil || g.limits == nil {
		return DefaultTrackerMaxTLP, nil
	}
	raw, err := g.limits.TrackerMaxTLP(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("read the tracker TLP limit: %w", err)
	}
	if raw == "" {
		return DefaultTrackerMaxTLP, nil
	}
	t := pentestdom.TLP(raw)
	if !slices.Contains(pentestdom.TLPsUpTo(pentestdom.TLPAmberStrict), t) {
		// Unknown, or red (never a limit): fail closed to the narrowest.
		return pentestdom.TLPClear, nil
	}
	return t, nil
}

// Check decides whether the findings' content may go to a tracker on route.
// It returns nil, an *EgressRefusedError, or a read error (fail closed).
// Callers check every finding whose content (or whose task's content) the
// request carries; the data scope of the person is applied before this.
func (g *EgressGate) Check(ctx context.Context, tenantID shared.ID, route Route, findings ...*vulnerability.Finding) error {
	var limit pentestdom.TLP
	limitRead := false
	campaigns := map[shared.ID]*pentestdom.Campaign{}
	for _, f := range findings {
		if !IsPentest(f) {
			continue
		}
		if route != RouteCampaign && route != RouteStatusSync {
			return &EgressRefusedError{Reason: ReasonPentestCampaignOnly}
		}
		cid := f.PentestCampaignID()
		if g == nil || g.campaigns == nil || cid == nil {
			return &EgressRefusedError{Reason: ReasonPentestNoCampaign}
		}
		c, ok := campaigns[*cid]
		if !ok {
			var err error
			c, err = g.campaigns.GetByID(ctx, tenantID, *cid)
			if err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					return &EgressRefusedError{Reason: ReasonPentestNoCampaign}
				}
				return fmt.Errorf("read the pentest campaign: %w", err)
			}
			campaigns[*cid] = c
		}
		if c == nil {
			return &EgressRefusedError{Reason: ReasonPentestNoCampaign}
		}
		if c.TLP() == pentestdom.TLPRed {
			return &EgressRefusedError{Reason: ReasonTLPRed, CampaignTLP: c.TLP()}
		}
		if !limitRead {
			var err error
			if limit, err = g.maxTLP(ctx, tenantID); err != nil {
				return err
			}
			limitRead = true
		}
		if c.TLP().Above(limit) {
			return &EgressRefusedError{Reason: ReasonTLPAboveLimit, CampaignTLP: c.TLP(), MaxTLP: limit}
		}
	}
	return nil
}

// Content is how much of a finding's text may leave for a tracker.
type Content int

const (
	// ContentFull: title, description and fix guidance (redacted and
	// encoded by the renderer).
	ContentFull Content = iota
	// ContentSecret: title and location only. No preview (masked value),
	// snippet, fingerprint, commit context or description (research 214
	// S-5).
	ContentSecret
	// ContentPersonalData: severity, counts and location only. No title,
	// description or other free text, which may carry the exposed data.
	ContentPersonalData
)

// IsSecret reports whether a finding is a leaked secret or credential.
func IsSecret(f *vulnerability.Finding) bool {
	return f.Source() == vulnerability.FindingSourceSecret || f.FindingType() == vulnerability.FindingTypeSecret
}

// CarriesPersonalData reports whether a finding exposes data: its data
// exposure risk is set to anything above none. Such findings may quote the
// exposed records (emails, user names), so no free text leaves.
func CarriesPersonalData(f *vulnerability.Finding) bool {
	r := f.DataExposureRisk()
	return r != "" && r != vulnerability.DataExposureRiskNone
}

// FindingContent is how much of the finding's text may leave. Secret wins
// over personal data (both drop the description; secret keeps the title,
// which the renderer redacts).
func FindingContent(f *vulnerability.Finding) Content {
	switch {
	case IsSecret(f):
		return ContentSecret
	case CarriesPersonalData(f):
		return ContentPersonalData
	}
	return ContentFull
}

// PersonalDataTitle is the title sent for a finding whose content level is
// ContentPersonalData.
const PersonalDataTitle = "Data exposure finding"

// OutboundTitle is the finding title a tracker may receive (the renderer
// still redacts and encodes it).
func OutboundTitle(f *vulnerability.Finding) string {
	if FindingContent(f) == ContentPersonalData {
		return PersonalDataTitle
	}
	return f.Title()
}
