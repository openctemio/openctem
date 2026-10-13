package sensor

import (
	"encoding/json"
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
