package scan

// Private targets on the organization's own sensors (RFC-054 §14, R5). An
// organization without scan zones used to have every private target refused
// (zone_none). Now such a target is admitted when the sensors that can take
// the job are the organization's own and their operator-written local policy
// allows private ranges: the host operator's policy is the authority, and the
// sensor's allow list decides each address. At the claim the claiming sensor
// itself must qualify (a platform sensor never does), so a job admitted at
// dispatch is refused at hand-out to any other sensor. Organizations with
// scan zones keep zone routing unchanged.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// PrivateTargetSensors answers whether private targets outside every scan
// zone may go to the tenant's own sensors (*postgres.SensorRepository).
type PrivateTargetSensors interface {
	PrivateTargetAdmission(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) (bool, error)
}

// SetPrivateTargetSensors wires the own-sensor rule for private targets.
// Without it a private target outside every zone is refused (fail closed).
func (s *Service) SetPrivateTargetSensors(p PrivateTargetSensors) { s.privateSensors = p }

// ownSensorsAdmitPrivate reports whether the tenant's own sensors may take
// private targets that no zone covers: the given sensor qualifies, or (no
// sensor yet) every dispatchable own sensor does.
func (s *Service) ownSensorsAdmitPrivate(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) (bool, error) {
	if s.privateSensors == nil {
		return false, nil
	}
	return s.privateSensors.PrivateTargetAdmission(ctx, tenantID, sensorID)
}

// ownSensorPrivate reports whether a target is a private address or range
// (RFC 1918, unique local, CGNAT) outside the built-in deny list: what the
// own-sensor rule may admit. Loopback, link-local and metadata addresses are
// never admitted.
func ownSensorPrivate(t string) bool {
	pt := scanzone.ParseTarget(t)
	return pt.IsAddr && scanzone.IsPrivate(pt.Prefix.Addr()) && !scanzone.IsDenied(pt.Prefix.Addr())
}

// admitOwnSensorPrivateTargets is admitZonedPrivateTargets for an
// organization without zones: the private targets the validator refused
// move to the returned list when the organization's own sensors may take
// them; otherwise their rejection says how to scan them.
func (s *Service) admitOwnSensorPrivateTargets(ctx context.Context, tenantID shared.ID, result *validator.TargetValidationResult, ownSensors bool, sensorID *shared.ID) ([]string, error) {
	own := false
	if ownSensors {
		var err error
		if own, err = s.ownSensorsAdmitPrivate(ctx, tenantID, sensorID); err != nil {
			return nil, err
		}
	}
	lenient := validator.NewTargetValidator(validator.WithAllowInternalIPs(true), validator.WithAllowLocalhost(false))
	var admitted []string
	remaining := result.Invalid[:0]
	for _, v := range result.Invalid {
		private := isInternalIPRejection(v.Error) && ownSensorPrivate(v.Original) && lenient.ValidateSingleTarget(v.Original).IsValid
		if private && own {
			admitted = append(admitted, v.Original)
			continue
		}
		if private {
			v.Error = "private address and no scan zone: run it on your own sensor whose local policy allows private ranges, or add a scan zone"
		}
		remaining = append(remaining, v)
	}
	result.Invalid = remaining
	result.HasErrors = len(remaining) > 0
	blocked := result.BlockedIPs[:0]
	for _, b := range result.BlockedIPs {
		if !own || !ownSensorPrivate(b) {
			blocked = append(blocked, b)
		}
	}
	result.BlockedIPs = blocked
	return admitted, nil
}
