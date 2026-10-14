package command

// Partial admission at claim time (research/130 follow-up): a pending scan
// command whose hosts are busy on only a few of its targets is split, so
// the targets on free hosts start now and the others wait in a follow-up
// command of the same step. The split is bounded (MaxHostSplits) and never
// gives either part a host key the command did not hold.

import (
	"context"
	"encoding/json"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxHostSplits bounds how often one command (and the follow-ups split from
// it) is split for busy hosts: a waiting part is split again only while its
// count is below it, so a step never fragments into one command per host.
const MaxHostSplits = 3

// HostPartition is a pending command's targets split by the hosts other
// tasks of its tenant hold now: Free can start, Blocked wait. Each part's
// keys are the command's keys its targets produce.
type HostPartition struct {
	Free, Blocked         []string
	FreeKeys, BlockedKeys []string
}

// PartitionHeld splits targets (of a command holding keys, in network) by
// held, the keys other tasks hold that conflict with the command's (the
// holders' own keys, as HostHoldersReader reports them): a target is
// blocked when one of its keys conflicts with a held key. ok is false when
// the command holds a key no target produces (keys computed some other way,
// or cut at politeness.MaxKeys): which part needs it cannot be told, so the
// command is never split.
func PartitionHeld(targets []string, network string, keys, held []string) (p HostPartition, ok bool) {
	heldSet := make(map[string]bool, len(held))
	for _, k := range held {
		heldSet[k] = true
	}
	produced := map[string]bool{}
	for _, t := range targets {
		own := followUpHostKeys(keys, []string{t}, network)
		blocked := false
		for _, k := range own {
			produced[k] = true
			for _, c := range HostKeyConflicts([]string{k}) {
				if heldSet[c] {
					blocked = true
				}
			}
		}
		if blocked {
			p.Blocked = append(p.Blocked, t)
		} else {
			p.Free = append(p.Free, t)
		}
	}
	for _, k := range keys {
		if !produced[k] {
			return HostPartition{}, false
		}
	}
	p.FreeKeys = followUpHostKeys(keys, p.Free, network)
	p.BlockedKeys = followUpHostKeys(keys, p.Blocked, network)
	return p, true
}

// Splittable reports whether the partition is worth a split: some targets
// can start and at most half of them wait. A command most of whose hosts
// are busy waits whole, so a step is not cut into a task per free host.
func (p HostPartition) Splittable() bool {
	return len(p.Free) > 0 && len(p.Blocked) > 0 && 2*len(p.Blocked) <= len(p.Free)+len(p.Blocked)
}

// HostSplit is one split to apply: the command narrowed to the free
// targets (Keep, its payload with their keys) and a new pending command
// with the blocked ones (Wait), of the same step and run.
type HostSplit struct {
	Keep     json.RawMessage
	KeepKeys []string
	Wait     json.RawMessage
	WaitKeys []string
}

// HostSplitter splits pending commands whose hosts are partly busy.
type HostSplitter interface {
	// HostSplitCandidates lists, oldest first, at most limit pending scan
	// commands of the tenant's run steps that sensorID may take (nil: an
	// unidentified poll), whose hosts are busy now and that were split
	// fewer than MaxHostSplits times.
	HostSplitCandidates(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, capabilities []string, limit int) ([]*Command, error)
	// SplitHostBusy applies s to cmd in one transaction: cmd (still
	// pending, its payload unchanged, split fewer than MaxHostSplits
	// times) takes Keep and KeepKeys, and a new pending command with Wait
	// and WaitKeys takes its placement (step, zone, gate, schedule, pin,
	// queue age, refusals). won is false, and nothing is written, when cmd
	// changed, was claimed or reached the bound meanwhile.
	SplitHostBusy(ctx context.Context, cmd *Command, s HostSplit) (sibling shared.ID, won bool, err error)
}
