package scanrun

// One canonical input per web origin (docs/architecture/scan-stages.md): a
// stage that takes web origins gets each origin once, as the http_service
// the HTTP probe found. The same service is not handed again as the bare
// host:port the port scan found, nor as the name or address the origin is
// served on; an open web port the probe found no origin on is not web
// input either. A non-web open port (SSH, SMTP, a database) still reaches a
// stage that declares open ports (network templates).

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

var httpServiceRef = asset.TypeRef{Type: asset.AssetTypeService, SubType: "http"}

// originHostPort returns the host and host:port an origin URL serves on
// (the scheme's default port when it names none).
func originHostPort(name string) (host, hostPort string, ok bool) {
	u, err := url.Parse(name)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", "", false
		}
	}
	host = strings.ToLower(u.Hostname())
	return host, net.JoinHostPort(host, port), true
}

// openPortHostPort returns the host and host:port of an open port stored as
// "host:port:proto" (or "host:port").
func openPortHostPort(name string) (host, hostPort string, port int, ok bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndex(n, ":"); i > 0 {
		switch n[i+1:] {
		case "tcp", "udp", "sctp":
			n = n[:i]
		}
	}
	h, p, err := net.SplitHostPort(n)
	if err != nil {
		return "", "", 0, false
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", "", 0, false
	}
	h = strings.Trim(h, "[]")
	return h, net.JoinHostPort(h, p), port, true
}

// canonicalWebInputs drops the outputs a web stage would get twice: names,
// addresses and open ports an origin of the same outputs covers, and, when
// the outputs hold origins (the probe ran), open web ports it found no HTTP
// on. Without any origin (a chain with no HTTP probe) the open ports are the
// only web input and stay. It counts what it drops under
// ReasonCoveredByOrigin. Stages that do not take web origins get the
// outputs unchanged.
func canonicalWebInputs(st stage.Stage, outputs []scanrun.StepOutput, skipped map[string]int) []scanrun.StepOutput {
	if !st.Accepts(httpServiceRef) {
		return outputs
	}
	hosts := map[string]bool{}
	hostPorts := map[string]bool{}
	for _, o := range outputs {
		if o.Type == string(asset.AssetTypeService) && o.SubType == "http" {
			if h, hp, ok := originHostPort(o.Name); ok {
				hosts[h], hostPorts[hp] = true, true
			}
		}
	}
	if len(hosts) == 0 {
		// No origin among the outputs (a chain without an HTTP probe): the
		// open ports are the only web input there is.
		return outputs
	}
	out := make([]scanrun.StepOutput, 0, len(outputs))
	for _, o := range outputs {
		switch {
		case o.Type == string(asset.AssetTypeService) && o.SubType == "open_port":
			_, hp, port, ok := openPortHostPort(o.Name)
			if ok && (hostPorts[hp] || isWebPort(port)) {
				skipped[scanrun.ReasonCoveredByOrigin]++
				continue
			}
		case o.Type == string(asset.AssetTypeDomain) || o.Type == string(asset.AssetTypeSubdomain) ||
			o.Type == string(asset.AssetTypeIPAddress):
			if hosts[strings.ToLower(strings.TrimSpace(o.Name))] {
				skipped[scanrun.ReasonCoveredByOrigin]++
				continue
			}
		}
		out = append(out, o)
	}
	return out
}

// webPorts are the ports an HTTP probe takes from an open port (the
// coverage policy's web port set).
var webPorts = map[int]bool{80: true, 443: true, 591: true, 3000: true, 5000: true, 8000: true, 8008: true,
	8080: true, 8081: true, 8088: true, 8443: true, 8888: true, 9000: true, 9443: true}

func isWebPort(p int) bool { return webPorts[p] }
