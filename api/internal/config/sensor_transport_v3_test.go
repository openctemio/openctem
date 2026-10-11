package config

import (
	"strings"
	"testing"
)

// SENSOR_TRANSPORT_V3: auto by default, off as the emergency switch,
// anything else refused at startup.
func TestLoad_SensorTransportV3Mode(t *testing.T) {
	for _, c := range []struct{ env, want string }{{"", TransportV3Auto}, {"auto", TransportV3Auto}, {" OFF ", TransportV3Off}} {
		t.Setenv("SENSOR_TRANSPORT_V3", c.env)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("SENSOR_TRANSPORT_V3=%q: %v", c.env, err)
		}
		if cfg.SensorConfig.TransportV3.Mode != c.want {
			t.Errorf("SENSOR_TRANSPORT_V3=%q: mode %q, want %q", c.env, cfg.SensorConfig.TransportV3.Mode, c.want)
		}
	}
	t.Setenv("SENSOR_TRANSPORT_V3", "grpc")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SENSOR_TRANSPORT_V3") {
		t.Fatalf("an unknown mode must be refused, got %v", err)
	}
}

// The old on/off flag is retired: a set value is refused, naming the switch.
func TestLoad_RefusesSensorTransportV3Enabled(t *testing.T) {
	t.Setenv("SENSOR_TRANSPORT_V3_ENABLED", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SENSOR_TRANSPORT_V3=auto|off") {
		t.Fatalf("want the retired flag refused, got %v", err)
	}
}

func TestSensorPublicHost(t *testing.T) {
	cases := []struct{ explicit, publicURL, appURL, want string }{
		{"sensors.corp.example:8443", "", "https://ctem.corp.example", "sensors.corp.example:8443"},
		{"192.168.8.204:8444", "", "https://192.168.8.204", "192.168.8.204:8444"},
		{"", "", "https://ctem.corp.example", "sensors.ctem.corp.example:443"},
		{"", "https://api.corp.example:9443", "https://ctem.corp.example", "sensors.api.corp.example:9443"},
		// An address cannot be routed by name: nothing derived.
		{"", "", "https://192.168.8.204", ""},
		{"", "", "https://[2001:db8::1]", ""},
		// No TLS, no name, nothing configured.
		{"", "", "http://ctem.corp.example", ""},
		{"", "", "https://localhost", ""},
		{"", "", "", ""},
	}
	for _, c := range cases {
		cfg := &Config{}
		cfg.SensorConfig.TransportV3.PublicHost = c.explicit
		cfg.SensorConfig.PublicAPIURL = c.publicURL
		cfg.App.URL = c.appURL
		if got := cfg.SensorPublicHost(); got != c.want {
			t.Errorf("explicit %q public %q app %q: %q, want %q", c.explicit, c.publicURL, c.appURL, got, c.want)
		}
	}
}
