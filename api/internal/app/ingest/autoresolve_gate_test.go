package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sensorRowRepo serves only GetByID (the sensor lookup of the tool gate);
// any other call panics via the nil embedded interface.
type sensorRowRepo struct {
	sensor.Repository
	rows map[shared.ID]*sensor.Sensor
}

func (r *sensorRowRepo) GetByID(_ context.Context, id shared.ID) (*sensor.Sensor, error) {
	if a, ok := r.rows[id]; ok {
		return a, nil
	}
	return nil, shared.ErrNotFound
}

// A sensor whose admin-assigned tools still say "gitleaks" (or an old sensor
// reporting "gitleaks") and a report Ingest has mapped to "betterleaks" name
// the same tool: the v2 tool check must not reject it.
func TestSensorToolChecksMatchAcrossTheGitleaksRename(t *testing.T) {
	if !SensorDeclaresTool([]string{"gitleaks"}, "betterleaks") || !SensorDeclaresTool([]string{"betterleaks"}, "gitleaks") {
		t.Fatal("SensorDeclaresTool must treat gitleaks and betterleaks as one tool")
	}
	if SensorDeclaresTool([]string{"gitleaks"}, "semgrep") {
		t.Fatal("the rename must not widen what a sensor may report")
	}
}
