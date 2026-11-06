package sensor

// The sensor's seccomp profile, served to install commands
// (docs/architecture/sensors.md, "Hardened installs").
//
// seccomp/sensor.json is the sensor release's docker/seccomp/sensor.json:
// the container runtime's default profile plus clone/unshare of new
// namespaces, so the sensor can give every tool task its own network
// namespace (per-task network confinement). The install snippets download
// it from the platform and check SeccompProfileSHA256, so a tampered or
// truncated download is refused before the container starts.

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

//go:embed seccomp/sensor.json
var seccompProfile []byte

// SeccompProfilePath is where the platform serves the profile (public: the
// file is part of the open-source sensor release and holds no tenant data).
const SeccompProfilePath = "/api/v1/sensors/install/seccomp-profile"

// SeccompProfileSHA256 is the hex SHA-256 of the served profile.
var SeccompProfileSHA256 = func() string {
	sum := sha256.Sum256(seccompProfile)
	return hex.EncodeToString(sum[:])
}()

// SeccompProfile returns a copy of the profile.
func SeccompProfile() []byte { return append([]byte(nil), seccompProfile...) }
