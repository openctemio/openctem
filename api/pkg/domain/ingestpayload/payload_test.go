package ingestpayload

import (
	"bytes"
	"crypto/sha256"
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

// A bound part (a queued sensor segment) opens only with the same binding:
// another report, segment number or content hash refuses it, and so does a
// part sealed without a binding opened with one (and the other way round).
func TestBoundPartOpensOnlyWithItsBinding(t *testing.T) {
	s, _ := NewSealer(key(1))
	tenant, job, report := shared.NewID(), shared.NewID(), shared.NewID()
	plain := []byte(`{"findings":[{"secret":"AKIA0000"}]}`)
	sum := sha256.Sum256(plain)
	binding := SensorSegmentBinding(report, 3, sum[:])
	p, err := s.SealBound(tenant, job, 0, "", binding, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(p.Sealed, []byte("AKIA")) {
		t.Fatal("sealed bytes carry the plaintext")
	}
	opened := func(mut func(*Part)) error {
		c := *p
		mut(&c)
		_, err := s.Open(&c)
		return err
	}
	if err := opened(func(*Part) {}); err != nil {
		t.Fatalf("same binding: %v", err)
	}
	other := sha256.Sum256([]byte("other"))
	for name, mut := range map[string]func(*Part){
		"other report":  func(c *Part) { c.Binding = SensorSegmentBinding(shared.NewID(), 3, sum[:]) },
		"other segment": func(c *Part) { c.Binding = SensorSegmentBinding(report, 4, sum[:]) },
		"other hash":    func(c *Part) { c.Binding = SensorSegmentBinding(report, 3, other[:]) },
		"no binding":    func(c *Part) { c.Binding = "" },
		"other tenant":  func(c *Part) { c.TenantID = shared.NewID() },
		"other job":     func(c *Part) { c.JobID = shared.NewID() },
	} {
		if err := opened(mut); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	unbound, _ := s.Seal(tenant, job, 0, "", plain)
	unbound.Binding = binding
	if _, err := s.Open(unbound); !errors.Is(err, ErrOpen) {
		t.Fatalf("unbound part opened with a binding: %v", err)
	}
}
