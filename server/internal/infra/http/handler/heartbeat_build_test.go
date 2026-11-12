package handler

import (
	"encoding/json"
	"testing"
)

// The sdk and sensor heartbeat members are read leniently: a member of an
// unexpected shape is ignored, never a reason to refuse the heartbeat.
func TestHeartbeatRequest_BuildReport(t *testing.T) {
	cases := []struct {
		body                       string
		sdkName, sdkVer, name, ver string
		commit, built              string
	}{
		{body: `{"sdk":{"name":"openctem-sdk-go","version":"0.9.0"},"sensor":{"name":"openctemio-sensor","version":"0.5.0","commit":"abc1234","build_time":"2026-10-01T00:00:00Z"}}`,
			sdkName: "openctem-sdk-go", sdkVer: "0.9.0", name: "openctemio-sensor", ver: "0.5.0", commit: "abc1234", built: "2026-10-01T00:00:00Z"},
		{body: `{"sdk":"openctem-sdk-go/0.9.0","sensor":["x"]}`},
		{body: `{"sdk":{"name":7,"version":{"x":1}},"sensor":{"version":"0.5.0"}}`, ver: "0.5.0"},
		{body: `{"status":"ok"}`},
	}
	for _, c := range cases {
		var req HeartbeatRequest
		if err := json.Unmarshal([]byte(c.body), &req); err != nil {
			t.Fatalf("%s: the heartbeat body was refused: %v", c.body, err)
		}
		got := req.buildReport()
		if got.SDKName != c.sdkName || got.SDKVersion != c.sdkVer || got.SensorName != c.name ||
			got.SensorVersion != c.ver || got.Commit != c.commit || got.BuildTime != c.built {
			t.Errorf("%s: %+v", c.body, got)
		}
	}
}
