package cirun

import (
	"encoding/json"
	"testing"
	"time"
)

// The longest known list an upload response carries stays far below what a
// client reads (8 MiB), with the widest entries (an accepted risk with an
// expiry and a large index).
func TestMaxKnownInResponseStaysSmall(t *testing.T) {
	exp := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	known := make([]KnownFinding, MaxKnownInResponse)
	for i := range known {
		known[i] = KnownFinding{Index: 99_999_999, Decision: DecisionFalsePositive,
			FindingID: "01a13d80-c1e4-7775-b4d9-e04681a7181a", ExpiresAt: &exp}
	}
	b, err := json.Marshal(known)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 2<<20 {
		t.Fatalf("known list of %d entries is %d bytes", MaxKnownInResponse, len(b))
	}
}
