package crypto

import "testing"

// F-9: test coverage for peppered hashing and legacy-compatible verification.

func TestHashTokenPeppered_Deterministic(t *testing.T) {
	const pepper = "pepper-secret-32bytes-xxxxxxxxxx"
	a := HashTokenPeppered("abc", pepper)
	b := HashTokenPeppered("abc", pepper)
	if a != b {
		t.Fatalf("peppered hash is not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(a))
	}
}

func TestHashTokenPeppered_DifferentPepperDifferentOutput(t *testing.T) {
	a := HashTokenPeppered("abc", "pepper-1")
	b := HashTokenPeppered("abc", "pepper-2")
	if a == b {
		t.Fatalf("different peppers should yield different outputs")
	}
}

func TestHashTokenPeppered_EmptyPepperFallsBackToLegacy(t *testing.T) {
	if HashTokenPeppered("abc", "") != HashToken("abc") {
		t.Fatalf("empty pepper must fall back to plain SHA-256 for compatibility")
	}
}

func TestVerifyTokenHashAny_AcceptsBothFormats(t *testing.T) {
	const pepper = "pepper-x"

	legacyStored := HashToken("mykey")
	pepperedStored := HashTokenPeppered("mykey", pepper)

	if !VerifyTokenHashAny("mykey", legacyStored, pepper) {
		t.Fatalf("failed to verify legacy hash with pepper set")
	}
	if !VerifyTokenHashAny("mykey", pepperedStored, pepper) {
		t.Fatalf("failed to verify peppered hash")
	}
	if VerifyTokenHashAny("wrong", legacyStored, pepper) {
		t.Fatalf("should not verify wrong token against legacy hash")
	}
	if VerifyTokenHashAny("wrong", pepperedStored, pepper) {
		t.Fatalf("should not verify wrong token against peppered hash")
	}
}

func TestVerifyTokenHashAny_NoPepper_AcceptsLegacy(t *testing.T) {
	legacyStored := HashToken("mykey")
	if !VerifyTokenHashAny("mykey", legacyStored, "") {
		t.Fatalf("must verify legacy hash when no pepper configured")
	}
}
