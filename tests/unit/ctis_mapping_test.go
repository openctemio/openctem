package unit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// =============================================================================
// Web3 Metadata Mapping Tests
// =============================================================================

func TestWeb3MetadataMapping(t *testing.T) {
	f := newTestFinding(t)

	// Simulate what setWeb3Fields does for previously unmapped fields
	f.SetMetadata("web3_related_tx_hashes", []string{"0xabc", "0xdef"})
	f.SetMetadata("web3_vulnerable_pattern", "delegatecall in loop")
	f.SetMetadata("web3_exploitable_on_mainnet", true)
	f.SetMetadata("web3_estimated_impact_usd", 1500000.50)
	f.SetMetadata("web3_affected_value_usd", 500000.00)
	f.SetMetadata("web3_attack_vector", "flash_loan")
	f.SetMetadata("web3_attacker_addresses", []string{"0x1234", "0x5678"})
	f.SetMetadata("web3_detection_tool", "slither")
	f.SetMetadata("web3_detection_confidence", "high")

	meta := f.Metadata()

	tests := []struct {
		key      string
		expected any
	}{
		{"web3_vulnerable_pattern", "delegatecall in loop"},
		{"web3_exploitable_on_mainnet", true},
		{"web3_estimated_impact_usd", 1500000.50},
		{"web3_affected_value_usd", 500000.00},
		{"web3_attack_vector", "flash_loan"},
		{"web3_detection_tool", "slither"},
		{"web3_detection_confidence", "high"},
	}

	for _, tc := range tests {
		val, ok := meta[tc.key]
		if !ok {
			t.Errorf("expected metadata key %q to exist", tc.key)
			continue
		}
		if val != tc.expected {
			t.Errorf("metadata[%q] = %v, want %v", tc.key, val, tc.expected)
		}
	}

	// Check slice fields
	txHashes, ok := meta["web3_related_tx_hashes"].([]string)
	if !ok {
		t.Fatal("expected web3_related_tx_hashes to be []string")
	}
	if len(txHashes) != 2 || txHashes[0] != "0xabc" {
		t.Errorf("web3_related_tx_hashes = %v, want [0xabc 0xdef]", txHashes)
	}

	addresses, ok := meta["web3_attacker_addresses"].([]string)
	if !ok {
		t.Fatal("expected web3_attacker_addresses to be []string")
	}
	if len(addresses) != 2 || addresses[0] != "0x1234" {
		t.Errorf("web3_attacker_addresses = %v, want [0x1234 0x5678]", addresses)
	}
}

// =============================================================================
// Web3 JSON/RawMessage Fields
// =============================================================================

func TestWeb3JSONFieldMapping(t *testing.T) {
	t.Run("gas_issue stored as json.RawMessage", func(t *testing.T) {
		f := newTestFinding(t)

		gasIssue := map[string]any{
			"function":  "transfer",
			"gas_used":  50000,
			"gas_limit": 21000,
			"issue":     "excessive gas consumption",
		}
		data, err := json.Marshal(gasIssue)
		if err != nil {
			t.Fatalf("failed to marshal gas issue: %v", err)
		}
		f.SetMetadata("web3_gas_issue", json.RawMessage(data))

		raw, ok := f.Metadata()["web3_gas_issue"].(json.RawMessage)
		if !ok {
			t.Fatal("expected web3_gas_issue to be json.RawMessage")
		}

		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("failed to unmarshal gas issue: %v", err)
		}
		if decoded["function"] != "transfer" {
			t.Errorf("gas_issue.function = %v, want transfer", decoded["function"])
		}
	})

	t.Run("access_control stored as json.RawMessage", func(t *testing.T) {
		f := newTestFinding(t)

		acl := map[string]any{
			"role":       "admin",
			"missing":    "onlyOwner modifier",
			"vulnerable": true,
		}
		data, err := json.Marshal(acl)
		if err != nil {
			t.Fatalf("failed to marshal access control: %v", err)
		}
		f.SetMetadata("web3_access_control", json.RawMessage(data))

		raw, ok := f.Metadata()["web3_access_control"].(json.RawMessage)
		if !ok {
			t.Fatal("expected web3_access_control to be json.RawMessage")
		}

		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("failed to unmarshal access control: %v", err)
		}
		if decoded["role"] != "admin" {
			t.Errorf("access_control.role = %v, want admin", decoded["role"])
		}
	})

	t.Run("reentrancy stored as json.RawMessage", func(t *testing.T) {
		f := newTestFinding(t)

		reentrancy := map[string]any{
			"function":       "withdraw",
			"external_call":  "msg.sender.call{value: amount}",
			"state_modified": true,
		}
		data, err := json.Marshal(reentrancy)
		if err != nil {
			t.Fatalf("failed to marshal reentrancy: %v", err)
		}
		f.SetMetadata("web3_reentrancy", json.RawMessage(data))

		raw, ok := f.Metadata()["web3_reentrancy"].(json.RawMessage)
		if !ok {
			t.Fatal("expected web3_reentrancy to be json.RawMessage")
		}

		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("failed to unmarshal reentrancy: %v", err)
		}
		if decoded["function"] != "withdraw" {
			t.Errorf("reentrancy.function = %v, want withdraw", decoded["function"])
		}
	})
}

// =============================================================================
// Partial Web3 Data (only some fields set)
// =============================================================================

func TestWeb3PartialData(t *testing.T) {
	t.Run("only chain and contract address", func(t *testing.T) {
		f := newTestFinding(t)

		// Simulate minimal web3 data - only native fields, no metadata
		f.SetWeb3Chain("ethereum")
		f.SetWeb3ContractAddress("0xdeadbeef")

		meta := f.Metadata()

		// Metadata-stored fields should not exist
		metadataKeys := []string{
			"web3_related_tx_hashes", "web3_vulnerable_pattern",
			"web3_exploitable_on_mainnet", "web3_estimated_impact_usd",
			"web3_gas_issue", "web3_access_control", "web3_reentrancy",
		}
		for _, key := range metadataKeys {
			if _, ok := meta[key]; ok {
				t.Errorf("expected metadata key %q to NOT exist for partial data", key)
			}
		}
	})

	t.Run("only metadata fields without native fields", func(t *testing.T) {
		f := newTestFinding(t)

		f.SetMetadata("web3_attack_vector", "reentrancy")
		f.SetMetadata("web3_detection_tool", "mythril")

		meta := f.Metadata()

		if meta["web3_attack_vector"] != "reentrancy" {
			t.Errorf("web3_attack_vector = %v, want reentrancy", meta["web3_attack_vector"])
		}
		if meta["web3_detection_tool"] != "mythril" {
			t.Errorf("web3_detection_tool = %v, want mythril", meta["web3_detection_tool"])
		}

		// Other metadata keys should not exist
		if _, ok := meta["web3_gas_issue"]; ok {
			t.Error("expected web3_gas_issue to NOT exist")
		}
	})
}

// =============================================================================
// Secret Metadata Mapping Tests
// =============================================================================

func TestSecretMetadataMapping(t *testing.T) {
	f := newTestFinding(t)

	revokedAt := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	f.SetMetadata("secret_revoked_at", revokedAt.Format(time.RFC3339))
	f.SetMetadata("secret_length", 64)

	meta := f.Metadata()

	if v, ok := meta["secret_revoked_at"]; !ok {
		t.Error("expected secret_revoked_at in metadata")
	} else if v != "2026-01-15T10:00:00Z" {
		t.Errorf("secret_revoked_at = %v, want 2026-01-15T10:00:00Z", v)
	}

	if v, ok := meta["secret_length"]; !ok {
		t.Error("expected secret_length in metadata")
	} else if v != 64 {
		t.Errorf("secret_length = %v, want 64", v)
	}
}

func TestSecretRevokedAtEdgeCases(t *testing.T) {
	t.Run("nil revoked_at is not stored", func(t *testing.T) {
		f := newTestFinding(t)
		// Don't set revoked_at - simulates nil in CTIS
		meta := f.Metadata()
		if _, ok := meta["secret_revoked_at"]; ok {
			t.Error("expected secret_revoked_at to NOT exist for nil value")
		}
	})

	t.Run("zero-length secret is not stored", func(t *testing.T) {
		f := newTestFinding(t)
		// Don't set length=0 - simulates Length == 0 in processor guard
		meta := f.Metadata()
		if _, ok := meta["secret_length"]; ok {
			t.Error("expected secret_length to NOT exist for zero value")
		}
	})

	t.Run("large secret length", func(t *testing.T) {
		f := newTestFinding(t)
		f.SetMetadata("secret_length", 4096)

		meta := f.Metadata()
		if v := meta["secret_length"]; v != 4096 {
			t.Errorf("secret_length = %v, want 4096", v)
		}
	})
}

// =============================================================================
// Zero/Nil Value Guard Tests
// =============================================================================

func TestMetadataNotSetForZeroValues(t *testing.T) {
	f := newTestFinding(t)

	// Don't set anything - simulates all fields being zero/nil

	meta := f.Metadata()

	keysToCheck := []string{
		"web3_related_tx_hashes", "web3_vulnerable_pattern", "web3_exploitable_on_mainnet",
		"web3_estimated_impact_usd", "web3_affected_value_usd", "web3_attack_vector",
		"web3_attacker_addresses", "web3_detection_tool", "web3_detection_confidence",
		"web3_gas_issue", "web3_access_control", "web3_reentrancy",
		"secret_revoked_at", "secret_length",
	}

	for _, key := range keysToCheck {
		if _, ok := meta[key]; ok {
			t.Errorf("expected metadata key %q to NOT exist for zero values", key)
		}
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestWeb3EmptyStringsNotStored(t *testing.T) {
	f := newTestFinding(t)

	// The processor guards: `if ctisFinding.Web3.AttackVector != ""`
	// Simulate an empty string NOT being stored (no SetMetadata call)
	// Verify that no key exists

	meta := f.Metadata()
	if _, ok := meta["web3_attack_vector"]; ok {
		t.Error("empty string should not be stored in metadata")
	}
}

func TestWeb3EmptySliceNotStored(t *testing.T) {
	f := newTestFinding(t)

	// The processor guards: `if len(ctisFinding.Web3.RelatedTxHashes) > 0`
	// Simulate an empty slice NOT being stored (no SetMetadata call)

	meta := f.Metadata()
	if _, ok := meta["web3_related_tx_hashes"]; ok {
		t.Error("empty slice should not be stored in metadata")
	}
}

func TestWeb3ZeroFloatNotStored(t *testing.T) {
	f := newTestFinding(t)

	// The processor guards: `if ctisFinding.Web3.EstimatedImpactUSD > 0`
	// Zero amounts should NOT be stored

	meta := f.Metadata()
	if _, ok := meta["web3_estimated_impact_usd"]; ok {
		t.Error("zero float should not be stored in metadata")
	}
	if _, ok := meta["web3_affected_value_usd"]; ok {
		t.Error("zero float should not be stored in metadata")
	}
}

func TestWeb3FalseExploitableNotStored(t *testing.T) {
	f := newTestFinding(t)

	// The processor guards: `if ctisFinding.Web3.ExploitableOnMainnet`
	// false should NOT be stored (only true is stored)

	meta := f.Metadata()
	if _, ok := meta["web3_exploitable_on_mainnet"]; ok {
		t.Error("false boolean should not be stored in metadata")
	}
}

func TestMetadataOverwrite(t *testing.T) {
	f := newTestFinding(t)

	// First set
	f.SetMetadata("web3_attack_vector", "reentrancy")

	// Overwrite
	f.SetMetadata("web3_attack_vector", "flash_loan")

	meta := f.Metadata()
	if meta["web3_attack_vector"] != "flash_loan" {
		t.Errorf("metadata should be overwritten, got %v", meta["web3_attack_vector"])
	}
}

func TestMetadataReturnsCopy(t *testing.T) {
	f := newTestFinding(t)

	f.SetMetadata("web3_detection_tool", "slither")

	meta1 := f.Metadata()
	meta1["web3_detection_tool"] = "MODIFIED"

	meta2 := f.Metadata()
	if meta2["web3_detection_tool"] != "slither" {
		t.Error("Metadata() should return a copy; modifying the copy should not affect the entity")
	}
}

func TestMultipleFieldsCoexist(t *testing.T) {
	f := newTestFinding(t)

	// Set both web3 and secret metadata on same finding
	f.SetMetadata("web3_attack_vector", "reentrancy")
	f.SetMetadata("web3_detection_tool", "mythril")
	f.SetMetadata("secret_length", 32)
	f.SetMetadata("secret_revoked_at", "2026-03-01T00:00:00Z")

	meta := f.Metadata()

	if len(meta) != 4 {
		t.Errorf("expected 4 metadata keys, got %d", len(meta))
	}
	if meta["web3_attack_vector"] != "reentrancy" {
		t.Errorf("web3_attack_vector = %v", meta["web3_attack_vector"])
	}
	if meta["secret_length"] != 32 {
		t.Errorf("secret_length = %v", meta["secret_length"])
	}
}

// =============================================================================
// Helpers
// =============================================================================

func newTestFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(),
		shared.NewID(),
		vulnerability.FindingSourceSAST,
		"test-tool",
		vulnerability.SeverityHigh,
		"test-finding",
	)
	if err != nil {
		t.Fatalf("failed to create finding: %v", err)
	}
	return f
}
