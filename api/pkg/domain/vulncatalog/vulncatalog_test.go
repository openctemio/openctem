package vulncatalog

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeFull, "full": ModeFull, " Disabled ": ModeDisabled} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// Degraded is a runtime state: it cannot be configured.
	for _, in := range []string{"degraded", "off", "legacy"} {
		if _, err := ParseMode(in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ParseMode(%q) err = %v, want a validation error", in, err)
		}
	}
}

// Every read of the disabled reader is "unknown", never an empty answer.
func TestDisabled_EveryReadIsUnavailable(t *testing.T) {
	ctx := context.Background()
	var r Reader = Disabled{}
	if r.Mode() != ModeDisabled {
		t.Fatalf("mode = %q", r.Mode())
	}
	check := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: err = %v, want ErrUnavailable", name, err)
		}
		if errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: unavailable must not read as not found", name)
		}
	}
	_, err := r.Version(ctx)
	check("Version", err)
	_, err = r.ResolveAlias(ctx, "cpe", "nginx:nginx")
	check("ResolveAlias", err)
	_, err = r.Product(ctx, shared.NewID())
	check("Product", err)
	ranges, err := r.Ranges(ctx, shared.NewID())
	check("Ranges", err)
	if ranges != nil {
		t.Fatal("Ranges returned ranges with an error")
	}
	_, err = r.Facts(ctx, []string{"CVE-2021-44228"})
	check("Facts", err)
	_, err = r.CVE(ctx, "CVE-2021-44228")
	check("CVE", err)
	_, err = r.CanonicalVulnID(ctx, "GHSA-jfh8-c2jp-5v3q")
	check("CanonicalVulnID", err)
	_, err = r.KEVSet(ctx)
	check("KEVSet", err)
	_, err = r.EPSS(ctx, []string{"CVE-2021-44228"})
	check("EPSS", err)
}

func TestNormalizeIDs(t *testing.T) {
	got, err := NormalizeIDs([]string{" cve-2021-44228", "CVE-2021-44228", "", "CVE-2024-1"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[CVE-2021-44228 CVE-2024-1]" {
		t.Fatalf("got %v", got)
	}
	if _, err := NormalizeIDs(make([]string, MaxBatch+1)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over the cap: err = %v", err)
	}
}

func TestErrNotFoundIsSharedNotFound(t *testing.T) {
	if !errors.Is(ErrNotFound, shared.ErrNotFound) {
		t.Fatal("ErrNotFound must wrap shared.ErrNotFound so handlers answer 404")
	}
}

func TestCanonicalForm(t *testing.T) {
	for in, want := range map[string]string{
		" cve-2021-44228 ":    "CVE-2021-44228",
		"ghsa-JFH8-c2jp-5v3q": "GHSA-jfh8-c2jp-5v3q",
		"GHSA-jfh8-c2jp-5v3q": "GHSA-jfh8-c2jp-5v3q",
		"pysec-2021-Abc":      "PYSEC-2021-Abc",
		"go-2022-0001":        "GO-2022-0001",
		"":                    "",
		"nodash":              "NODASH",
	} {
		if got := CanonicalForm(in); got != want {
			t.Errorf("CanonicalForm(%q) = %q, want %q", in, got, want)
		}
	}
}
