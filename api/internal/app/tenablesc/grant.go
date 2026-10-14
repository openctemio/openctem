package tenablesc

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GrantReader reads a sensor's grant (RFC-052). Satisfied by the sensor
// grant repository.
type GrantReader interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error)
}

// SetGrantReader makes sync requests and scan commands check the
// connector sensor's grant before they are queued. Without it they are
// queued and the claim's grant gate alone decides (a refused command then
// waits until it expires).
func (s *Service) SetGrantReader(g GrantReader) { s.grants = g }

// grantRefusalCode: the connector sensor's grant does not allow the command
// (job type, tool, tier, target scope …). The claim would withhold it, so it
// is not queued; the message names what to widen on the sensor's grant.
const grantRefusalCode = "CONNECTOR_GRANT_REFUSES"

// grantRefuses is the refusal error for r.
func grantRefuses(r *sensordom.GrantRefusal) error {
	return shared.NewDomainError(grantRefusalCode,
		"the connector sensor's grant does not allow this ("+r.Dimension+": "+r.Detail+
			"); an administrator can allow it on the sensor's grant (job types connector_sync and connector_scan, tool tenable_sc, trusted, tier T1 for scans)",
		shared.ErrConflict)
}

// admitGrant checks one connector command against the sensor's grant, as
// the claim will (an unzoned command: connector scans run outside every
// scan zone). This is a pre-check for a clear answer now, not the
// authority: the claim checks again and fails closed. A grant that cannot
// be read here is left to the claim.
func (s *Service) admitGrant(ctx context.Context, tenantID, sensorID shared.ID, typ command.CommandType, payload json.RawMessage) error {
	if s.grants == nil {
		return nil
	}
	g, err := s.grants.Get(ctx, tenantID, sensorID)
	if err != nil || g == nil {
		return nil //nolint:nilerr // the claim decides when the grant cannot be read
	}
	if r := g.Admit(string(typ), payload, nil); r != nil {
		return grantRefuses(r)
	}
	return nil
}

// IsGrantRefusal reports whether err is the grant pre-check's refusal.
func IsGrantRefusal(err error) bool {
	var de *shared.DomainError
	return errors.As(err, &de) && de.Code == grantRefusalCode
}
