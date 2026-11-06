package exposure

import (
	"errors"
	"testing"

	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCategoryEventTypes(t *testing.T) {
	got, err := categoryEventTypes([]string{"hijackable_subdomains"}, nil)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v %v", got, err)
	}
	// Intersected with an explicit type filter.
	got, err = categoryEventTypes([]string{"hijackable_subdomains"}, []exposuredom.EventType{exposuredom.EventTypeDanglingNS, exposuredom.EventTypePortOpen})
	if err != nil || len(got) != 1 || got[0] != exposuredom.EventTypeDanglingNS {
		t.Fatalf("got %v %v", got, err)
	}
	// No overlap keeps the filter closed instead of dropping it.
	got, err = categoryEventTypes([]string{"dns"}, []exposuredom.EventType{exposuredom.EventTypePortOpen})
	if err != nil || len(got) != 1 || got[0].IsValid() {
		t.Fatalf("an empty intersection must match nothing: %v %v", got, err)
	}
	if _, err := categoryEventTypes([]string{"bogus"}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown category: %v", err)
	}
}

func TestCategoryCounts(t *testing.T) {
	got := CategoryCounts(map[string]int64{"port_open": 2, "service_detected": 1, "dangling_cname": 4, "weird": 1})
	if got["exposed_ports"] != 3 || got["hijackable_subdomains"] != 4 || got["other"] != 1 {
		t.Fatalf("got %v", got)
	}
}
