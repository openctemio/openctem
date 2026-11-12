package sensortransport

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

// On the gRPC binding the sensor is known before its message is read: one
// sensor may hold at most MaxUnaryPerSensor unary calls in flight, so it
// cannot buffer many full-size messages before its rate budget applies.
// Other sensors and control streams are not affected.
func TestAdmitSensorUnary_BoundsOneSensor(t *testing.T) {
	s := NewServer(Config{MaxUnaryPerSensor: 2}, nil, logger.NewNop())
	unary := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, sensorv3connect.SensorServicePutResultProcedure, nil)
	}
	var releases []func()
	for range 2 {
		rel, ok := s.admitSensorUnary(httptest.NewRecorder(), unary(), "sensor-a")
		if !ok {
			t.Fatal("a call within the bound was refused")
		}
		releases = append(releases, rel)
	}
	rec := httptest.NewRecorder()
	if _, ok := s.admitSensorUnary(rec, unary(), "sensor-a"); ok || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a third call of the same sensor: ok=%v status=%d, want refused with 503", ok, rec.Code)
	}
	if _, ok := s.admitSensorUnary(httptest.NewRecorder(), unary(), "sensor-b"); !ok {
		t.Fatal("another sensor was refused")
	}
	stream := httptest.NewRequest(http.MethodPost, sensorv3connect.SensorServiceSubscribeProcedure, nil)
	if _, ok := s.admitSensorUnary(httptest.NewRecorder(), stream, "sensor-a"); !ok {
		t.Fatal("a control stream must not need a unary slot")
	}
	releases[0]()
	if _, ok := s.admitSensorUnary(httptest.NewRecorder(), unary(), "sensor-a"); !ok {
		t.Fatal("a released slot was not reusable")
	}
}
