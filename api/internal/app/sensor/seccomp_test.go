package sensor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The served profile is the sensor release's file (sensor
// docker/seccomp/sensor.json, byte for byte): a change here is deliberate
// and must come from a sensor release, together with this digest.
const releasedSeccompSHA256 = "97d0b0a8292012537f2474b6c200ea49bef1239a306bc6e7e8a2afe15a3895a8"

func TestSeccompProfile_IsTheReleasedFile(t *testing.T) {
	if SeccompProfileSHA256 != releasedSeccompSHA256 {
		t.Fatalf("profile digest %s, want the sensor release's %s", SeccompProfileSHA256, releasedSeccompSHA256)
	}
	var p struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []any  `json:"syscalls"`
	}
	if err := json.Unmarshal(SeccompProfile(), &p); err != nil || p.DefaultAction != "SCMP_ACT_ERRNO" || len(p.Syscalls) == 0 {
		t.Fatalf("not a deny-by-default seccomp profile: %+v err %v", p.DefaultAction, err)
	}
	b := SeccompProfile()
	b[0] = 'x'
	if SeccompProfile()[0] == 'x' {
		t.Fatal("SeccompProfile hands out the embedded bytes")
	}
}

// The bundled Compose sensor runs with api/deploy/sensor/seccomp.json: the
// same file the install commands download, so both follow one sensor release
// (CI's "Sensor install" job compares it with that release).
func TestSeccompProfile_BundledSensorUsesTheSameFile(t *testing.T) {
	deployed, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "sensor", "seccomp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(deployed, SeccompProfile()) {
		t.Fatal("api/deploy/sensor/seccomp.json differs from internal/app/sensor/seccomp/sensor.json: copy the sensor release's docker/seccomp/sensor.json to both")
	}
}
