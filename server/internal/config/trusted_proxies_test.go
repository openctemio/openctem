package config

import (
	"reflect"
	"testing"
)

// A whole container network as a trusted proxy is reported; the gateway's
// and the web server's own addresses are not.
func TestWideTrustedProxies(t *testing.T) {
	c := &Config{}
	c.Server.TrustedProxies = []string{"172.20.0.10", "172.20.0.11/32", "10.0.0.0/28", "172.18.0.0/16", " 10.1.0.0/27 ", "fd00::/64", "fd00::1/128", "bad"}
	c.SensorConfig.TransportV3.MTLSTrustedProxies = []string{"172.18.0.0/16", "172.18.0.5/32"}
	want := []string{
		"SERVER_TRUSTED_PROXIES=172.18.0.0/16",
		"SERVER_TRUSTED_PROXIES=10.1.0.0/27",
		"SERVER_TRUSTED_PROXIES=fd00::/64",
		"SENSOR_MTLS_TRUSTED_PROXIES=172.18.0.0/16",
	}
	if got := c.WideTrustedProxies(); !reflect.DeepEqual(got, want) {
		t.Fatalf("WideTrustedProxies() = %v, want %v", got, want)
	}
	if got := (&Config{}).WideTrustedProxies(); len(got) != 0 {
		t.Fatalf("no proxies: got %v", got)
	}
}
