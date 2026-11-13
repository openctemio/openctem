package scangov

// Asset owners as approvers (RFC-073 §10): the model only. A rule may say
// that the owners of the scanned assets approve, each their own part of
// the targets, with a fallback group for targets nobody owns. Until the
// request and gate paths enforce it, Normalize refuses the setting, so a
// saved rule never claims a control that is not applied.

import (
	"slices"
	"sort"
	"strings"
)

// Approver sources of a requirement.
const (
	// ApproversRule: the rule's roles and named people (default).
	ApproversRule = "rule"
	// ApproversAssetOwners: each owner of the scanned assets approves the
	// targets they own; targets nobody owns go to the fallback group.
	ApproversAssetOwners = "asset_owners"
)

// assetOwnerApproversEnforced turns on ApproversAssetOwners once the
// request and gate paths apply it.
const assetOwnerApproversEnforced = false

// OwnerKind is who owns a part: one person, one group, or nobody (the
// fallback).
type OwnerKind string

// Owner kinds.
const (
	OwnerUser     OwnerKind = "user"
	OwnerGroup    OwnerKind = "group"
	OwnerFallback OwnerKind = "fallback"
)

// TargetOwners is one target and the owners of the asset behind it (its
// user and group owners; none when nobody owns it or no asset is known).
type TargetOwners struct {
	Target   string
	UserIDs  []string
	GroupIDs []string
}

// Part is the share of a scan's targets one owner approves.
type Part struct {
	Kind OwnerKind `json:"kind"`
	// ID: the user or group id; the fallback group id for OwnerFallback
	// ("" when the rule's approvers stand in).
	ID      string   `json:"id,omitempty"`
	Targets []string `json:"targets"`
}

// Key names the part.
func (p Part) Key() string { return string(p.Kind) + ":" + p.ID }

// SplitByOwner groups the targets by owner: a target owned by several
// owners appears in each of their parts (every owner of a target approves
// it); a target nobody owns goes to the fallback part, owned by
// fallbackGroup. Parts are ordered users, groups, fallback, then by id;
// targets are sorted.
func SplitByOwner(targets []TargetOwners, fallbackGroup string) []Part {
	byKey := map[string]*Part{}
	add := func(kind OwnerKind, id, target string) {
		k := string(kind) + ":" + id
		p := byKey[k]
		if p == nil {
			p = &Part{Kind: kind, ID: id}
			byKey[k] = p
		}
		if !slices.Contains(p.Targets, target) {
			p.Targets = append(p.Targets, target)
		}
	}
	for _, t := range targets {
		owned := false
		for _, u := range t.UserIDs {
			if u = strings.ToLower(strings.TrimSpace(u)); u != "" {
				add(OwnerUser, u, t.Target)
				owned = true
			}
		}
		for _, g := range t.GroupIDs {
			if g = strings.ToLower(strings.TrimSpace(g)); g != "" {
				add(OwnerGroup, g, t.Target)
				owned = true
			}
		}
		if !owned {
			add(OwnerFallback, strings.ToLower(strings.TrimSpace(fallbackGroup)), t.Target)
		}
	}
	rank := map[OwnerKind]int{OwnerUser: 0, OwnerGroup: 1, OwnerFallback: 2}
	out := make([]Part, 0, len(byKey))
	for _, p := range byKey {
		sort.Strings(p.Targets)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// PartApprovers answers who may approve a part: the owner user, the
// members of the owner group, the fallback group's members (or, with no
// fallback group, the rule's approvers).
type PartApprovers func(p Part) []string

// PartsApproved reports whether every part has an approval from one of its
// approvers who is not the requester, and returns the keys of the parts
// still waiting. An approval counts for every part its approver may
// approve; with no parts nothing is approved.
func PartsApproved(parts []Part, approvals []Approval, requester string, approversOf PartApprovers) (bool, []string) {
	if len(parts) == 0 {
		return false, nil
	}
	var waiting []string
	for _, p := range parts {
		allowed := approversOf(p)
		ok := false
		for _, a := range approvals {
			if a.UserID != requester && !a.Self && slices.Contains(allowed, a.UserID) {
				ok = true
				break
			}
		}
		if !ok {
			waiting = append(waiting, p.Key())
		}
	}
	return len(waiting) == 0, waiting
}

func (q Requirement) normalizedApprovers() (Requirement, error) {
	switch q.ApproverSource = strings.ToLower(strings.TrimSpace(q.ApproverSource)); q.ApproverSource {
	case "", ApproversRule:
		q.ApproverSource = ""
		if q.FallbackGroupID != "" {
			return q, invalid("fallback_group_id is for asset_owners approvers")
		}
		return q, nil
	case ApproversAssetOwners:
		if !assetOwnerApproversEnforced {
			return q, invalid("asset_owners approvers are not available yet")
		}
		q.FallbackGroupID = strings.ToLower(strings.TrimSpace(q.FallbackGroupID))
		if q.FallbackGroupID != "" && !isUUID(q.FallbackGroupID) {
			return q, invalid("fallback_group_id must be a group id")
		}
		return q, nil
	}
	return q, invalid("approver_source must be rule or asset_owners")
}
