package command

// Partial admission at claim time (pkg/domain/command/host_split.go): when
// a sensor has free scan slots the queue cannot fill, a pending command of
// a run step whose hosts are busy on only a few of its targets is split.
// The targets on free hosts stay in the command, which the same claim then
// takes; the others wait in a new command of the same step and run, signed
// and handed out like any other when their hosts are free.

import (
	"context"
	"encoding/json"
	"fmt"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxHostHoldersForSplit bounds the holders read for one command. Missing
// some only leaves a target in the part that starts, where the claim's own
// host check (under its locks) still holds it back: never two tasks on one
// host.
const maxHostHoldersForSplit = 200

// admitHostBusy splits up to want commands sensorID may take whose hosts
// are partly busy, and returns how many it split. Failures are logged and
// split nothing: the commands keep waiting whole, as before.
func (s *Service) admitHostBusy(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, capabilities []string, want int) int {
	splitter, ok := s.repo.(commanddom.HostSplitter)
	holders, ok2 := s.repo.(commanddom.HostHoldersReader)
	if !ok || !ok2 || want <= 0 {
		return 0
	}
	cands, err := splitter.HostSplitCandidates(ctx, tenantID, sensorID, capabilities, 2*want)
	if err != nil {
		s.logger.Warn("commands waiting for hosts could not be read", "tenant_id", tenantID.String(), "error", err)
		return 0
	}
	n := 0
	for _, c := range cands {
		if n >= want {
			break
		}
		split, err := s.planHostSplit(ctx, holders, c)
		if err != nil {
			s.logger.Warn("cannot split a command waiting for hosts", "command_id", c.ID.String(), "error", err)
			continue
		}
		if split == nil {
			continue
		}
		sibling, won, err := splitter.SplitHostBusy(ctx, c, *split)
		if err != nil {
			s.logger.Warn("cannot split a command waiting for hosts", "command_id", c.ID.String(), "error", err)
			continue
		}
		if won {
			n++
			s.logger.Info("command split: targets on free hosts start now, the others wait",
				"tenant_id", tenantID.String(), "command_id", c.ID.String(), "waiting_command_id", sibling.String(),
				"starting", len(split.KeepKeys), "waiting_keys", len(split.WaitKeys))
			observeHostSplit()
		}
	}
	return n
}

// planHostSplit is the split of c by the hosts other tasks hold now; nil
// when it should wait whole (no held host, most of its targets blocked, or
// keys that cannot be attributed to targets).
func (s *Service) planHostSplit(ctx context.Context, holders commanddom.HostHoldersReader, c *commanddom.Command) (*commanddom.HostSplit, error) {
	keys, hs, err := holders.HostHolders(ctx, c.TenantID, c.ID, maxHostHoldersForSplit)
	if err != nil {
		return nil, err
	}
	var held []string
	for _, h := range hs {
		held = append(held, h.Keys...)
	}
	targets := commanddom.PayloadTargets(c.Payload)
	p, ok := commanddom.PartitionHeld(targets, payloadNetwork(c.Payload), keys, held)
	if !ok || !p.Splittable() {
		return nil, nil
	}
	keep, err := narrowPayload(c.Payload, p.Free)
	if err == nil {
		keep, err = withPayloadHostKeys(keep, p.FreeKeys)
	}
	if err != nil {
		return nil, err
	}
	wait, err := narrowPayload(c.Payload, p.Blocked)
	if err == nil {
		wait, err = withPayloadHostKeys(wait, p.BlockedKeys)
	}
	if err != nil {
		return nil, err
	}
	return &commanddom.HostSplit{Keep: keep, KeepKeys: p.FreeKeys, Wait: wait, WaitKeys: p.BlockedKeys}, nil
}

// payloadNetwork is the payload's network_id ("" when none).
func payloadNetwork(payload json.RawMessage) string {
	var p struct {
		Network string `json:"network_id"`
	}
	_ = json.Unmarshal(payload, &p)
	return p.Network
}

// withPayloadHostKeys sets the payload's host_keys, the keys the sensor
// admits the command under, to keys.
func withPayloadHostKeys(payload json.RawMessage, keys []string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("command payload: %w", err)
	}
	if keys == nil {
		keys = []string{}
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	fields["host_keys"] = b
	return json.Marshal(fields)
}

// scanCount counts the scan commands of cmds.
func scanCount(cmds []*commanddom.Command) int {
	n := 0
	for _, c := range cmds {
		if c.Type == commanddom.CommandTypeScan {
			n++
		}
	}
	return n
}
