package sensor

// Host pressure ranks sensors (research/318): a sensor whose host stalls
// ranks behind one that does not, and a stale report counts for nothing.

import (
	"testing"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

func pressured(name, level string, reportedAgo time.Duration) *sensordom.Sensor {
	at := time.Now().Add(-reportedAgo)
	return &sensordom.Sensor{
		Name: name, MaxConcurrentJobs: 5,
		Load: sensordom.LoadReport{
			Resources:  &sensordom.ReportedResources{Pressure: &sensordom.ReportedPressure{Level: level}},
			ReportedAt: &at,
		},
	}
}

func TestSelectLeastLoaded_PrefersLessPressuredSensor(t *testing.T) {
	s := &SensorSelector{weights: sensordom.DefaultLoadBalancingWeights()}
	for name, tc := range map[string]struct {
		a, b string
		want string
	}{
		"ok beats elevated":         {sensordom.PressureElevated, sensordom.PressureOK, "b"},
		"elevated beats overloaded": {sensordom.PressureOverloaded, sensordom.PressureElevated, "b"},
		"first wins a tie":          {sensordom.PressureOK, sensordom.PressureOK, "a"},
	} {
		got := s.selectLeastLoaded([]*sensordom.Sensor{pressured("a", tc.a, time.Minute), pressured("b", tc.b, time.Minute)})
		if got == nil || got.Name != tc.want {
			t.Errorf("%s: picked %v, want %s", name, got, tc.want)
		}
	}
	// Stale pressure is ignored: both rank equal, the first stays.
	got := s.selectLeastLoaded([]*sensordom.Sensor{
		pressured("a", sensordom.PressureElevated, time.Hour), pressured("b", sensordom.PressureOK, time.Hour)})
	if got == nil || got.Name != "a" {
		t.Errorf("stale pressure changed the choice: %v", got)
	}
}

func TestPressureScore(t *testing.T) {
	now := time.Now()
	for level, want := range map[string]float64{
		"": 0, sensordom.PressureOK: 0, sensordom.PressureElevated: 25, sensordom.PressureOverloaded: 100,
	} {
		if got := pressureScore(pressured("x", level, time.Minute), now); got != want {
			t.Errorf("%q: score %v, want %v", level, got, want)
		}
	}
	if got := pressureScore(pressured("x", sensordom.PressureOverloaded, time.Hour), now); got != 0 {
		t.Errorf("stale overloaded scored %v", got)
	}
}
