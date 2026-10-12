package sensortransport

import (
	"context"
	"encoding/pem"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// Per-sensor issuance budget: a burst of 5, then one every 10 minutes. A
// sensor renews once every few days; a stolen key must not mint a stream of
// certificates.
const (
	issueRatePerSecond = 1.0 / 600.0
	issueBurst         = 5
)

// EventRecorder writes sensor timeline events (sensorapp.SensorService).
type EventRecorder interface {
	RecordEvents(ctx context.Context, events []sensordom.Event)
}

// Issuer issues client certificates (IssueCertificate, RFC-059 T7).
type Issuer struct {
	ca       *CA
	keys     KeyResolver
	events   EventRecorder
	ttl      time.Duration
	endpoint string
	limiter  *middleware.TelemetryRateLimiter
	log      *logger.Logger
	now      func() time.Time
}

// NewIssuer builds the issuer. endpoint is the gRPC binding's host:port the
// answer names; events may be nil.
func NewIssuer(ca *CA, keys KeyResolver, events EventRecorder, ttl time.Duration, endpoint string, log *logger.Logger) *Issuer {
	return &Issuer{
		ca: ca, keys: keys, events: events, ttl: ClampCertTTL(ttl), endpoint: endpoint,
		limiter: middleware.NewTelemetryRateLimiter(issueRatePerSecond, issueBurst, 2*time.Hour, log),
		log:     log.With("component", "sensor-ca"), now: time.Now,
	}
}

var errNotKeyBound = errors.New("certificates are issued to key-bound sensors only")

// Issue certifies the registered key the caller authenticated with. The key
// is read again from the store (active, sensor not revoked, not paused), so
// a certificate is never issued for a key that no longer holds.
func (i *Issuer) Issue(ctx context.Context, id sensorapp.SensorIdentity) (*sensorv3.IssueCertificateResponse, error) {
	thumb := id.KeyThumbprint()
	if thumb == "" || id.Sensor == nil || id.Sensor.TenantID == nil {
		return nil, connect.NewError(connect.CodePermissionDenied, errNotKeyBound)
	}
	if !i.limiter.Allow(id.Sensor.ID.String()) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("certificate issuance budget exhausted; retry later"))
	}
	fresh, pub, err := i.keys.SigningIdentity(ctx, thumb, false)
	if err != nil || fresh.Sensor == nil || fresh.Sensor.ID != id.Sensor.ID || fresh.Sensor.TenantID == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sensor identity no longer valid"))
	}
	tid, sid := fresh.Sensor.TenantID.String(), fresh.Sensor.ID.String()
	cert, err := i.ca.IssueClient(pub, tid, sid, i.ttl)
	if err != nil {
		i.log.Error("failed to issue a sensor certificate", "sensor_id", sid, "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("certificate not issued"))
	}
	renew := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	if i.events != nil {
		i.events.RecordEvents(ctx, []sensordom.Event{sensordom.NewEvent(*fresh.Sensor.TenantID, fresh.Sensor.ID,
			sensordom.EventCertificateIssued, i.now(), "Client certificate issued for protocol v3",
			map[string]any{"not_after": cert.NotAfter.UTC().Format(time.RFC3339), "key_thumbprint": thumb})})
	}
	return &sensorv3.IssueCertificateResponse{
		CertificateChainPem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.DER})),
		CaBundlePem:         i.ca.CertificatePEM(),
		NotBefore:           timestamppb.New(cert.NotBefore),
		NotAfter:            timestamppb.New(cert.NotAfter),
		RenewAfter:          timestamppb.New(renew),
		GrpcEndpoint:        i.endpoint,
	}, nil
}
