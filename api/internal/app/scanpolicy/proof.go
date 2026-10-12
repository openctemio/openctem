package scanpolicy

// Ownership proof before platform sensors scan (RFC-054 §8.1): a platform
// setting, "Require a verified domain before platform sensors scan a target".
// Default off: a self-hosted operator runs its own infrastructure and the
// organization's scope entry is the authorization. A public multi-tenant
// cloud turns it on as an abuse control: platform sensors send packets from
// the operator's addresses, so a tenant must prove it owns a domain before
// they probe it, and intrusive (T2) probes need that proof on any sensor.
//
// Threat model: turning it off lets any organization point platform sensors
// at any name its scope entries cover, so the change is the same as the scan
// approval policy's: super_admin with a fresh console authenticator code
// (handler) and a reason, a critical admin audit row, and the other platform
// administrators emailed. No tenant route writes it. The scope gate, the
// deny list, scan zones for private addresses, exclusions and tier ceilings
// do not read it and stay in force either way. An unreadable stored value
// counts as on (fail closed); a value never stored is the default, off.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProofSettingKey is the platform_settings key of the proof requirement.
const ProofSettingKey = "platform_sensor_proof"

// ActionProofChanged is the admin audit action of a change.
const ActionProofChanged = "platform.platform_sensor_proof_changed"

// ProofStore persists the proof requirement (platform_settings). The
// returned version is 0 when nothing is stored.
type ProofStore interface {
	GetProofRequired(ctx context.Context) (bool, int, error)
	SetProofRequired(ctx context.Context, required bool, expectedVersion int, by string, at time.Time) (int, error)
}

func (s *Service) proofStore() (ProofStore, error) {
	ps, ok := s.repo.(ProofStore)
	if !ok || ps == nil {
		return nil, errors.New("the proof setting store is not wired")
	}
	return ps, nil
}

// ProofSetting returns the stored requirement and its version (0: nothing
// stored, the default off applies).
func (s *Service) ProofSetting(ctx context.Context) (bool, int, error) {
	s.mu.Lock()
	if s.proofCached != nil && time.Since(s.proofAt) < cacheTTL {
		v, ver := *s.proofCached, s.proofVer
		s.mu.Unlock()
		return v, ver, nil
	}
	s.mu.Unlock()
	ps, err := s.proofStore()
	if err != nil {
		return false, 0, err
	}
	v, ver, err := ps.GetProofRequired(ctx)
	if errors.Is(err, ErrNotFound) {
		v, ver, err = false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	s.mu.Lock()
	s.proofCached, s.proofVer, s.proofAt = &v, ver, time.Now()
	s.mu.Unlock()
	return v, ver, nil
}

// PlatformProofRequired reports whether platform sensors (and intrusive
// probes) need a verified domain now. An unreadable setting answers true.
func (s *Service) PlatformProofRequired(ctx context.Context) bool {
	v, _, err := s.ProofSetting(ctx)
	if err != nil {
		s.log.Warn("platform sensor proof setting unreadable; proof required", "error", err)
		return true
	}
	return v
}

// UpdateProof changes the requirement. The caller checked super_admin and a
// fresh authenticator code.
func (s *Service) UpdateProof(ctx context.Context, required bool, expectedVersion int, c Change) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	ps, err := s.proofStore()
	if err != nil {
		return 0, err
	}
	prev, _, err := s.ProofSetting(ctx)
	if err != nil {
		return 0, err
	}
	v, err := ps.SetProofRequired(ctx, required, expectedVersion, c.Actor.ID().String(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.proofCached, s.proofVer, s.proofAt = &required, v, time.Now()
	s.mu.Unlock()
	s.recordKey(ctx, c, ActionProofChanged, ProofSettingKey, onOff(prev), onOff(required))
	s.mailOthers(ctx, c, "[Scans] Verified domain requirement for platform sensors changed",
		fmt.Sprintf("%s changed \"Require a verified domain before platform sensors scan a target\" from %s to %s. Reason: %s",
			c.Actor.Email(), onOff(prev), onOff(required), strings.TrimSpace(c.Reason)))
	return v, nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
