package bountyprogram

// Outbound delivery of events about private program assets (RFC-065 §15.4).
//
// Tenant integrations are organization-wide channels: a Slack channel, a
// webhook or a SIEM index reaches people who are not members of a private
// program. An event (notification, automation trigger) about an asset that
// only private programs list is therefore restricted: it goes only to the
// integrations a member attached to one of those programs, unless an owner
// allowed organization-wide channels for every one of them. An event about
// an asset the organization also owns goes out as usual, but the names and
// tags of private programs are scrubbed from it for every destination not
// attached to that program.

import (
	"context"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScrubbedProgram replaces a private program's name, handle or tag in an
// outbound payload.
const ScrubbedProgram = "[private program]"

// minScrubLen is the shortest program name or handle that is scrubbed: a
// one- or two-letter name would mangle unrelated words.
const minScrubLen = 3

// DeliverySubject names what an event is about. Every id is resolved
// within the tenant; ids of another tenant match nothing.
type DeliverySubject struct {
	AssetIDs    []shared.ID
	FindingIDs  []shared.ID
	ExposureIDs []shared.ID
	ApprovalIDs []shared.ID
}

// Empty reports whether the subject names nothing (an event about no
// asset, such as a sensor or scope notice).
func (s DeliverySubject) Empty() bool {
	return len(s.AssetIDs)+len(s.FindingIDs)+len(s.ExposureIDs)+len(s.ApprovalIDs) == 0
}

// DeliveryProgram is a private program linked to an event's assets, with
// the strings that identify it in a payload.
type DeliveryProgram struct {
	ID     shared.ID
	Name   string
	Handle string
	Tag    string // program:<platform>:<slug>, the derived system tag
}

// Delivery is the routing decision for one event.
type Delivery struct {
	// Restricted holds, for each restricted asset of the event, the private
	// programs that list it. A destination receives the event only if it is
	// attached to one program of every set.
	Restricted [][]shared.ID
	// Programs are the private programs linked to any of the event's
	// assets; their names are scrubbed for destinations not attached to
	// them.
	Programs []DeliveryProgram
	// Channels maps an integration id to the programs (of Programs) it is
	// attached to.
	Channels map[shared.ID]map[shared.ID]bool
}

// IsRestricted reports whether the event concerns an asset only private
// programs list (and not every one of them allows organization channels).
func (d Delivery) IsRestricted() bool { return len(d.Restricted) > 0 }

// Allows reports whether the integration may receive the event.
func (d Delivery) Allows(integrationID shared.ID) bool {
	attached := d.Channels[integrationID]
	for _, set := range d.Restricted {
		ok := false
		for _, p := range set {
			if attached[p] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Scrub removes, from text bound for the integration, the names, handles
// and tags of the private programs it is not attached to (case-insensitive).
func (d Delivery) Scrub(integrationID shared.ID, text string) string {
	if text == "" || len(d.Programs) == 0 {
		return text
	}
	attached := d.Channels[integrationID]
	var terms []string
	for _, p := range d.Programs {
		if attached[p.ID] {
			continue
		}
		// The tag first: it contains the slug, which may equal the handle.
		for _, t := range []string{p.Tag, p.Name, p.Handle} {
			if t = strings.TrimSpace(t); len([]rune(t)) >= minScrubLen {
				terms = append(terms, regexp.QuoteMeta(t))
			}
		}
	}
	if len(terms) == 0 {
		return text
	}
	re := regexp.MustCompile(`(?i)` + strings.Join(terms, "|"))
	return re.ReplaceAllString(text, ScrubbedProgram)
}

// DeliveryResolver resolves routing decisions for outbound events.
type DeliveryResolver interface {
	// Resolve returns the routing decision for an event about subject.
	// An error means the decision is unknown: callers must not deliver.
	Resolve(ctx context.Context, tenantID shared.ID, subject DeliverySubject) (Delivery, error)
	// RestrictedAssets returns the ids (of assetIDs) of restricted assets.
	RestrictedAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error)
}

// Channel is an integration attached to a program.
type Channel struct {
	IntegrationID shared.ID
	Name          string
	Provider      string
	CreatedBy     *shared.ID
}

// DeliveryStore keeps a program's delivery settings.
type DeliveryStore interface {
	// Channels lists the integrations attached to the program.
	Channels(ctx context.Context, tenantID, programID shared.ID) ([]Channel, error)
	// AttachChannel attaches a notification integration of the tenant;
	// ErrChannelNotFound when the tenant has no such integration.
	AttachChannel(ctx context.Context, tenantID, programID, integrationID shared.ID, by *shared.ID) error
	// DetachChannel detaches it; ErrChannelNotFound when it was not attached.
	DetachChannel(ctx context.Context, tenantID, programID, integrationID shared.ID) error
	// OrgChannels reports whether the program allows organization channels.
	OrgChannels(ctx context.Context, tenantID, programID shared.ID) (bool, error)
	// SetOrgChannels sets it.
	SetOrgChannels(ctx context.Context, tenantID, programID shared.ID, enabled bool) error
}

// ErrChannelNotFound: the integration is not a notification integration of
// the tenant, or is not attached to the program.
var ErrChannelNotFound = shared.NewDomainError("PROGRAM_CHANNEL_NOT_FOUND", "notification integration not found", shared.ErrNotFound)
