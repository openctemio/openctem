package handler

// People and provenance on scope entries and exclusions (research/53 §4.6).
// Every actor field of a scope response is an ActorRef: a person of this
// organization with their name, a former member (no name), or the platform
// with a code the web translates. Names come only from this tenant's
// memberships; an id outside the tenant resolves to nothing (a "former
// member"), so no other organization's user is ever named. No e-mail is
// returned. Audit snapshots record the reference without the name.

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ActorRef is who did something to a scope entry or exclusion.
type ActorRef struct {
	// Kind: user or system.
	Kind string `json:"kind"`
	// ID is the user id (kind user).
	ID string `json:"id,omitempty"`
	// Name is the member's display name; empty for a former member.
	Name string `json:"name,omitempty"`
	// FormerMember: the user is no longer a member of this organization.
	FormerMember bool `json:"former_member,omitempty"`
	// Code names a platform write (kind system): upgrade_wildcard_split,
	// seed_migration or system.
	Code string `json:"code,omitempty"`
}

// Actor kinds and system codes.
const (
	ActorKindUser   = "user"
	ActorKindSystem = "system"

	ActorCodeWildcardSplit = "upgrade_wildcard_split"
	ActorCodeSeedMigration = "seed_migration"
	ActorCodeSystem        = "system"
)

// actorRef reads a stored actor ("" = none; a user id; or "system:…").
func actorRef(raw string) *ActorRef {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if id, err := shared.IDFromString(raw); err == nil {
		return &ActorRef{Kind: ActorKindUser, ID: id.String()}
	}
	switch raw {
	case "system:migration-000292":
		return &ActorRef{Kind: ActorKindSystem, Code: ActorCodeWildcardSplit}
	case "system:seed-migration":
		return &ActorRef{Kind: ActorKindSystem, Code: ActorCodeSeedMigration}
	}
	return &ActorRef{Kind: ActorKindSystem, Code: ActorCodeSystem}
}

// MemberNamer names the members of a tenant (*postgres.ScopeActorRepository).
type MemberNamer interface {
	// MemberNames maps the given user ids that are current members of the
	// tenant to their display names; any other id is absent.
	MemberNames(ctx context.Context, tenantID shared.ID, userIDs []string) (map[string]string, error)
}

// resolveActors fills the names of the user references. A lookup failure
// leaves the references unnamed (the ids still identify them); it never
// fails the request.
func resolveActors(ctx context.Context, namer MemberNamer, log *logger.Logger, tenantID string, refs []*ActorRef) {
	if namer == nil {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	ids := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, r := range refs {
		if r != nil && r.Kind == ActorKindUser && !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	names, err := namer.MemberNames(ctx, tid, ids)
	if err != nil {
		if log != nil {
			log.Warn("scope actors: member names", "error", logger.SanitizeError(err))
		}
		return
	}
	for _, r := range refs {
		if r == nil || r.Kind != ActorKindUser {
			continue
		}
		if n, ok := names[r.ID]; ok {
			r.Name = n
		} else {
			r.FormerMember = true
		}
	}
}

// actorRefs collects the actor references of scope responses.
func targetActorRefs(list ...*ScopeTargetResponse) []*ActorRef {
	out := []*ActorRef{}
	for _, t := range list {
		if t == nil {
			continue
		}
		out = append(out, t.CreatedBy, t.RejectedBy)
		for i := range t.Approvals {
			out = append(out, t.Approvals[i].Approver)
		}
	}
	return out
}

func exclusionActorRefs(list ...*ScopeExclusionResponse) []*ActorRef {
	out := []*ActorRef{}
	for _, e := range list {
		if e != nil {
			out = append(out, e.CreatedBy, e.ApprovedBy, e.RejectedBy)
		}
	}
	return out
}
