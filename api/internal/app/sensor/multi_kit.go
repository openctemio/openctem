package sensor

// The multi-sensor kit's command (the sensor repository's deploy/multi,
// sensors.sh): several sensors on one host, each with its own identity,
// volume and network. The console shows it beside the single-sensor
// installs; it pairs like them (docs/architecture/sensor-pairing.md).

import "strings"

// MultiKitGuideURL is where the kit and its set-up steps are published.
const MultiKitGuideURL = "https://github.com/openctemio/sensor/tree/main/deploy/multi"

// MultiKitCommand renders the kit's "add" command for one sensor: the
// platform URL, the console's pairing code (empty: the sensor prints one)
// and the platform CA pin (empty: a publicly trusted certificate). Every
// value is shell-quoted; pins must already be validated hex (CAPins).
func MultiKitCommand(name, apiURL, pairingCode, caPins string) string {
	var b strings.Builder
	b.WriteString("# Several sensors on one host: set up the multi-sensor kit (sensors.sh) once,\n")
	b.WriteString("# as its guide says: " + MultiKitGuideURL + "\n")
	b.WriteString("# Then, in the kit's directory, add this sensor. It starts, prints its pairing\n")
	b.WriteString("# code, the link to approve it on and its fingerprint, and ends once paired.\n")
	b.WriteString("./sensors.sh add " + shellQuote(name) + " --api-url " + shellQuote(apiURL))
	if pairingCode != "" {
		b.WriteString(" --pairing-code " + shellQuote(pairingCode))
	}
	if caPins != "" && caPinsRE.MatchString(caPins) {
		b.WriteString(" --ca-sha256 " + caPins)
	}
	b.WriteString("\n")
	return b.String()
}

// MultiKitPrivateNote follows MultiKitCommand for a sensor that scans
// internal networks: the kit has no flag for the private-target switch, so
// the host owner sets it in the sensor's environment.
const MultiKitPrivateNote = "# This sensor scans internal networks: add SENSOR_ALLOW_PRIVATE_TARGETS=1 to its\n" +
	"# environment in the kit (the guide shows where), or the host refuses private addresses.\n"
