package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The shared-sensor check uses the one deny list shared with sensors (ctis
// addrscope): reserved IPv4 ranges, multicast, IPv6 forms that carry an
// internal IPv4 address, and a range that only holds internal space past
// its first address are internal too, as literals and as name answers.
func TestPlatformTargetRefusal_InternalAddressForms(t *testing.T) {
	ctx := context.Background()
	res := mapResolver{addrs: map[string][]string{
		"nat64.example.com":  {"64:ff9b::a00:1"},
		"sixto4.example.com": {"2002:a00:1::1"},
		"public.example.com": {"64:ff9b::808:808"},
	}}
	svc := &Service{logger: logger.NewNop(), zoneResolver: res}
	for target, refused := range map[string]bool{
		"0.0.0.0":                 true,
		"0.1.2.3":                 true,
		"192.0.0.8":               true,
		"198.18.0.1":              true,
		"224.0.0.251":             true,
		"255.255.255.255":         true,
		"64:ff9b::a00:1":          true,
		"2002:a00:1::1":           true,
		"[64:ff9b::a9fe:a9fe]:80": true,
		"8.0.0.0/6":               true, // holds 10.0.0.0/8
		"2130706433":              true, // inet_aton forms of 127.0.0.1
		"http://0x7f.1/":          true,
		"0177.0.0.1:8080":         true,
		"8.8.8.0/24":              false,
		"64:ff9b::808:808":        false, // NAT64 of 8.8.8.8
		"nat64.example.com":       true,
		"sixto4.example.com":      true,
		"public.example.com":      false,
	} {
		err := svc.PlatformTargetRefusal(ctx, shared.NewID(), []string{target}, false)
		var de *shared.DomainError
		if got := errors.As(err, &de) && de.Code == codePlatformRefused; got != refused {
			t.Errorf("%s: refused=%v (%v), want %v", target, got, err, refused)
		}
	}
}
