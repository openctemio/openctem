package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type refuseAllCI struct{ asked int }

func (r *refuseAllCI) Refused(context.Context, *sensordom.Sensor, string, string) bool {
	r.asked++
	return true
}

// Protocol v3 is refused what protocol v2 refuses after authentication: the
// organization "OIDC required for CI" policy applies to an identity that
// reached the in-process v2 routes over v3.
func TestAuthenticateInProcessWithPolicies_AppliesCIPolicy(t *testing.T) {
	h := NewSensorResultsV2Handler(nil, nil, logger.NewNop())
	policy := &refuseAllCI{}
	h.SetCIRunnerKeyPolicy(policy)
	tid := shared.NewID()
	id := sensorapp.SensorIdentity{Sensor: &sensordom.Sensor{ID: shared.NewID(), TenantID: &tid,
		ExecutionMode: sensordom.ExecutionModeStandalone}}

	reached := false
	mw := h.AuthenticateInProcessWithPolicies(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest(http.MethodPut, protov2.PathPrefix+"/results/"+shared.NewID().String(), nil)
	req = req.WithContext(WithSensorIdentity(req.Context(), id))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if reached || policy.asked != 1 || !strings.Contains(rec.Body.String(), string(protov2.ProblemCIOIDCRequired)) {
		t.Fatalf("reached=%v asked=%d status=%d body=%s", reached, policy.asked, rec.Code, rec.Body.String())
	}
}
