package httpsec

import (
	"context"
	"net"
	"strings"
	"testing"
)

// The allow-all switch is a development convenience: in any other APP_ENV it
// is refused and nothing is opened, so a production process keeps every
// private range blocked even if it never checks PrivateEgressError.
func TestLoadPrivateEgress(t *testing.T) {
	for name, tc := range map[string]struct {
		env, all, cidrs string
		wantAll         bool
		wantNets        []string
		wantErr         string
	}{
		"unset":                         {env: "production"},
		"switch in development":         {env: "development", all: "1", wantAll: true},
		"switch off":                    {env: "production", all: "0"},
		"switch in production refused":  {env: "production", all: "1", wantErr: "APP_ENV=development"},
		"switch in staging refused":     {env: "staging", all: "1", wantErr: "APP_ENV=development"},
		"switch value other than 1":     {env: "development", all: "yes", wantErr: "must be empty"},
		"named ranges":                  {env: "production", cidrs: " 10.20.0.0/16 ,192.168.7.0/24,fd12:3456::/48,", wantNets: []string{"10.20.0.0/16", "192.168.7.0/24", "fd12:3456::/48"}},
		"public range refused":          {env: "production", cidrs: "203.0.113.0/24", wantErr: "not inside a private range"},
		"wider than private refused":    {env: "production", cidrs: "172.0.0.0/8", wantErr: "not inside a private range"},
		"CGNAT refused":                 {env: "production", cidrs: "100.64.0.0/10", wantErr: "not inside a private range"},
		"link-local refused":            {env: "development", cidrs: "169.254.0.0/16", wantErr: "not inside a private range"},
		"bad entry refuses the rest":    {env: "production", cidrs: "10.20.0.0/16,nonsense", wantErr: "not a CIDR"},
		"switch refused drops the list": {env: "production", all: "1", cidrs: "10.20.0.0/16", wantErr: "APP_ENV=development"},
	} {
		t.Run(name, func(t *testing.T) {
			all, nets, err := loadPrivateEgress(tc.env, tc.all, tc.cidrs)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if all || len(nets) != 0 {
					t.Fatalf("a refused setting opened something: all=%v nets=%v", all, nets)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			got := make([]string, 0, len(nets))
			for _, n := range nets {
				got = append(got, n.String())
			}
			if all != tc.wantAll || strings.Join(got, ",") != strings.Join(tc.wantNets, ",") {
				t.Fatalf("all=%v nets=%v, want all=%v nets=%v", all, got, tc.wantAll, tc.wantNets)
			}
		})
	}
}

// A named range opens that range only: the rest of the private space, and
// every hard-blocked address inside a named range (the IPv6 metadata
// endpoints sit inside fc00::/7), stay blocked.
func TestIsIPBlocked_NamedPrivateRanges(t *testing.T) {
	_, nets, err := loadPrivateEgress("production", "", "10.20.0.0/16,fd00:ec2::/32")
	if err != nil {
		t.Fatal(err)
	}
	prevAll, prevNets := allowPrivate, allowedPrivateCIDRs
	allowPrivate, allowedPrivateCIDRs = false, nets
	defer func() { allowPrivate, allowedPrivateCIDRs = prevAll, prevNets }()

	for ip, blocked := range map[string]bool{
		"10.20.1.5":     false,
		"10.21.0.1":     true,
		"192.168.1.1":   true,
		"172.16.0.1":    true,
		"fd00:ec2::1":   false,
		"fd00:ec2::254": true, // AWS IMDS over IPv6, hard-blocked
		"127.0.0.1":     true,
		"8.8.8.8":       false,
	} {
		if got := IsIPBlocked(net.ParseIP(ip)); got != blocked {
			t.Errorf("IsIPBlocked(%s) = %v, want %v", ip, got, blocked)
		}
	}
	if err := ValidateHost(context.Background(), "10.20.1.5:25"); err != nil {
		t.Errorf("named range refused: %v", err)
	}
	if err := ValidateHost(context.Background(), "10.30.1.5:25"); err == nil {
		t.Error("private address outside the named ranges admitted")
	}
	if got := strings.Join(AllowedPrivateCIDRs(), ","); got != "10.20.0.0/16,fd00:ec2::/32" {
		t.Errorf("AllowedPrivateCIDRs = %q", got)
	}
}
