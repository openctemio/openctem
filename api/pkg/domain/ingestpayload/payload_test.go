package ingestpayload

import (
	"bytes"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := NewSealer(key(1))
	if err != nil {
		t.Fatal(err)
	}
	tenant, job := shared.NewID(), shared.NewID()
	plain := bytes.Repeat([]byte(`{"finding":"x"}`), 1000)
	p, err := s.Seal(tenant, job, 0, "results.sarif", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(p.Sealed, []byte(`finding`)) {
		t.Fatal("sealed bytes carry the plaintext")
	}
	if len(p.Sealed) >= len(plain) {
		t.Fatalf("sealed %d bytes for %d: not compressed", len(p.Sealed), len(plain))
	}
	got, err := s.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip changed the bytes")
	}
}

// A part copied to another tenant, job or part number, or opened with
// another key, does not open.
func TestOpenRefusesAMovedOrTamperedPart(t *testing.T) {
	s, _ := NewSealer(key(1))
	tenant, job := shared.NewID(), shared.NewID()
	p, err := s.Seal(tenant, job, 0, "", []byte("report"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *Part){
		"other tenant": func(c *Part) { c.TenantID = shared.NewID() },
		"other job":    func(c *Part) { c.JobID = shared.NewID() },
		"other part":   func(c *Part) { c.Part = 1 },
		"tampered":     func(c *Part) { c.Sealed = append([]byte(nil), c.Sealed...); c.Sealed[len(c.Sealed)-1] ^= 1 },
		"bad digest":   func(c *Part) { c.Digest = make([]byte, 32) },
		"bigger size":  func(c *Part) { c.SizeBytes++ },
		"unknown key":  func(c *Part) { c.KeyID = "0000000000000000" },
	}
	for name, mutate := range cases {
		c := *p
		mutate(&c)
		if _, err := s.Open(&c); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: err = %v, want ErrOpen", name, err)
		}
	}
	other, _ := NewSealer(key(2))
	if _, err := other.Open(p); !errors.Is(err, ErrOpen) {
		t.Errorf("other master key: err = %v, want ErrOpen", err)
	}
}

func TestRotationOpensPartsOfThePreviousKey(t *testing.T) {
	old, _ := NewSealer(key(1))
	tenant, job := shared.NewID(), shared.NewID()
	p, _ := old.Seal(tenant, job, 2, "", []byte("report"))
	rotated, err := NewSealer(key(2), key(1))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.Open(p); err != nil || string(got) != "report" {
		t.Fatalf("open after rotation: %q, %v", got, err)
	}
}

func TestSealerRefusesWithoutKeyAndOverLimits(t *testing.T) {
	var zero *Sealer
	if _, err := zero.Seal(shared.NewID(), shared.NewID(), 0, "", nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("nil sealer: %v", err)
	}
	if _, err := NewSealer([]byte("short")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("short key: %v", err)
	}
	s, _ := NewSealer(key(1))
	if _, err := s.Seal(shared.NewID(), shared.NewID(), MaxParts, "", nil); err == nil {
		t.Fatal("part number over the limit was sealed")
	}
}
