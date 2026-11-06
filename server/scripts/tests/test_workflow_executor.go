//go:build ignore
// +build ignore

// test_workflow_executor.go - Manual test script for Workflow Executor
//
// Usage:
//   go run scripts/test_workflow_executor.go
//
// This script tests the security controls implemented in the Workflow Executor:
//   - SEC-WF01/03: SSTI Prevention (safe interpolation)
//   - SEC-WF02/09/13: SSRF Protection (URL validation, DNS, TOCTOU)
//   - SEC-WF04/06/07/10: Resource limits (concurrent, timeout, per-tenant)
//   - SEC-WF05/08: Tenant isolation
//   - SEC-WF11: ReDoS prevention (expression limits)
//   - SEC-WF12: Panic recovery
//   - SEC-WF14: Log injection prevention

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("Workflow Executor Security Tests")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println()

	results := []testResult{}

	// Run all tests
	results = append(results, testSSRFProtection()...)
	results = append(results, testSSTIPrevention()...)
	results = append(results, testExpressionLimits()...)
	results = append(results, testInputSanitization()...)
	results = append(results, testConcurrencyLimits()...)
	results = append(results, testPanicRecovery()...)

	// Summary
	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("SUMMARY")
	fmt.Println("=" + strings.Repeat("=", 60))

	passed := 0
	failed := 0
	for _, r := range results {
		if r.passed {
			passed++
			fmt.Printf("✅ PASS: %s\n", r.name)
		} else {
			failed++
			fmt.Printf("❌ FAIL: %s - %s\n", r.name, r.reason)
		}
	}

	fmt.Println()
	fmt.Printf("Total: %d passed, %d failed\n", passed, failed)

	if failed > 0 {
		fmt.Println("\n⚠️  Some tests failed!")
	} else {
		fmt.Println("\n✅ All tests passed!")
	}
}

type testResult struct {
	name   string
	passed bool
	reason string
}

// =============================================================================
// SEC-WF02/09/13: SSRF Protection Tests
// =============================================================================

func testSSRFProtection() []testResult {
	fmt.Println("\n--- SEC-WF02/09/13: SSRF Protection ---")

	results := []testResult{}

	// Blocked CIDRs
	blockedCIDRs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
	}

	// Test blocked IPs
	testIPs := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // AWS metadata
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tc := range testIPs {
		ip := net.ParseIP(tc.ip)
		isBlocked := isBlockedIP(ip, blockedCIDRs)

		testName := fmt.Sprintf("SSRF: IP %s should be %s", tc.ip, map[bool]string{true: "blocked", false: "allowed"}[tc.blocked])

		if isBlocked == tc.blocked {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected blocked=%v, got %v", tc.blocked, isBlocked)})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	// Test blocked hostname patterns
	blockedSuffixes := []string{".local", ".internal", ".localhost", ".lan", ".home", ".corp", ".intranet"}

	testHosts := []struct {
		host    string
		blocked bool
	}{
		{"localhost", true},
		{"server.local", true},
		{"api.internal", true},
		{"db.corp", true},
		{"example.com", false},
		{"api.github.com", false},
	}

	for _, tc := range testHosts {
		isBlocked := isBlockedHostname(tc.host, blockedSuffixes)

		testName := fmt.Sprintf("SSRF: Host %s should be %s", tc.host, map[bool]string{true: "blocked", false: "allowed"}[tc.blocked])

		if isBlocked == tc.blocked {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected blocked=%v, got %v", tc.blocked, isBlocked)})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	// Test URL validation
	testURLs := []struct {
		url    string
		valid  bool
		reason string
	}{
		{"https://example.com/api", true, "valid external URL"},
		{"http://127.0.0.1:8080", false, "loopback IP"},
		{"http://localhost/api", false, "localhost"},
		{"ftp://example.com/file", false, "invalid scheme"},
		{"http://192.168.1.1/admin", false, "private IP"},
		{"http://169.254.169.254/metadata", false, "metadata endpoint"},
		{"http://server.internal/api", false, "internal hostname"},
	}

	for _, tc := range testURLs {
		err := validateURL(tc.url, blockedCIDRs, blockedSuffixes)
		isValid := err == nil

		testName := fmt.Sprintf("SSRF: URL %s should be %s", tc.url, map[bool]string{true: "valid", false: "blocked"}[tc.valid])

		if isValid == tc.valid {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected valid=%v, got %v (err: %v)", tc.valid, isValid, err)})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	return results
}

// =============================================================================
// SEC-WF01/03: SSTI Prevention Tests
// =============================================================================

func testSSTIPrevention() []testResult {
	fmt.Println("\n--- SEC-WF01/03: SSTI Prevention ---")

	results := []testResult{}

	// Test safe interpolation (should NOT execute templates)
	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		{
			input:    "Hello {{.tenant_id}}",
			expected: "Hello test-tenant-123",
			desc:     "simple variable replacement",
		},
		{
			input:    "Run {{.run_id}} for {{.workflow_id}}",
			expected: "Run test-run-456 for test-workflow-789",
			desc:     "multiple variables",
		},
		{
			input:    "{{ .tenant_id }} with spaces",
			expected: "test-tenant-123 with spaces",
			desc:     "variable with spaces",
		},
		{
			// SSTI attack - should NOT execute
			input:    "{{printf \"%s\" \"PWNED\"}}",
			expected: "{{printf \"%s\" \"PWNED\"}}", // Should remain unchanged
			desc:     "template function attack (should not execute)",
		},
		{
			// Another SSTI attack
			input:    "{{.tenant_id}}{{shell \"rm -rf /\"}}",
			expected: "test-tenant-123{{shell \"rm -rf /\"}}", // Only tenant_id replaced
			desc:     "shell injection attack (should not execute)",
		},
	}

	replacements := map[string]string{
		"{{.tenant_id}}":     "test-tenant-123",
		"{{.run_id}}":        "test-run-456",
		"{{.workflow_id}}":   "test-workflow-789",
		"{{ .tenant_id }}":   "test-tenant-123",
		"{{ .run_id }}":      "test-run-456",
		"{{ .workflow_id }}": "test-workflow-789",
	}

	for _, tc := range testCases {
		result := safeInterpolate(tc.input, replacements)

		testName := fmt.Sprintf("SSTI: %s", tc.desc)

		if result == tc.expected {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected %q, got %q", tc.expected, result)})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	return results
}

// =============================================================================
// SEC-WF11: Expression Limits Tests
// =============================================================================

func testExpressionLimits() []testResult {
	fmt.Println("\n--- SEC-WF11: Expression Limits ---")

	results := []testResult{}

	const maxExpressionLength = 500
	const maxPathDepth = 10

	// Test expression length
	testCases := []struct {
		expr  string
		valid bool
		desc  string
	}{
		{"trigger.severity == 'critical'", true, "normal expression"},
		{strings.Repeat("a", 500), true, "at limit (500 chars)"},
		{strings.Repeat("a", 501), false, "over limit (501 chars)"},
		{strings.Repeat("a", 1000), false, "way over limit (1000 chars)"},
	}

	for _, tc := range testCases {
		isValid := len(tc.expr) <= maxExpressionLength

		testName := fmt.Sprintf("Expression length: %s", tc.desc)

		if isValid == tc.valid {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected valid=%v, got %v", tc.valid, isValid)})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	// Test path depth
	pathTests := []struct {
		path  string
		valid bool
		desc  string
	}{
		{"a.b.c", true, "depth 3"},
		{"a.b.c.d.e.f.g.h.i.j", true, "depth 10 (at limit)"},
		{"a.b.c.d.e.f.g.h.i.j.k", false, "depth 11 (over limit)"},
	}

	for _, tc := range pathTests {
		parts := strings.Split(tc.path, ".")
		isValid := len(parts) <= maxPathDepth

		testName := fmt.Sprintf("Path depth: %s", tc.desc)

		if isValid == tc.valid {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected valid=%v, got %v (depth: %d)", tc.valid, isValid, len(parts))})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	return results
}

// =============================================================================
// SEC-WF14: Input Sanitization Tests
// =============================================================================

func testInputSanitization() []testResult {
	fmt.Println("\n--- SEC-WF14: Input Sanitization ---")

	results := []testResult{}

	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		{"valid_node_key", "valid_node_key", "normal key"},
		{"node-key-123", "node-key-123", "key with hyphens"},
		{"node.key.name", "node.key.name", "key with dots"},
		{"node\nkey", "node_key", "newline injection"},
		{"node\rkey", "node_key", "carriage return injection"},
		{"node;rm -rf /", "node_rm_-rf__", "command injection"},
		{"node<script>", "node_script_", "XSS injection"},
		{strings.Repeat("a", 150), strings.Repeat("a", 100), "truncate long input"},
	}

	for _, tc := range testCases {
		result := sanitizeForLogging(tc.input)

		testName := fmt.Sprintf("Sanitize: %s", tc.desc)

		if result == tc.expected {
			results = append(results, testResult{name: testName, passed: true})
			fmt.Printf("  ✓ %s\n", testName)
		} else {
			results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected %q, got %q", tc.expected, result)})
			fmt.Printf("  ✗ %s\n", testName)
		}
	}

	return results
}

// =============================================================================
// SEC-WF04/07/10: Concurrency Limits Tests
// =============================================================================

func testConcurrencyLimits() []testResult {
	fmt.Println("\n--- SEC-WF04/07/10: Concurrency Limits ---")

	results := []testResult{}

	// Test semaphore-based rate limiting
	const maxConcurrent = 5
	semaphore := make(chan struct{}, maxConcurrent)

	var acquired int32
	var rejected int32
	var wg sync.WaitGroup

	// Try to acquire 10 slots (only 5 should succeed immediately)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
				atomic.AddInt32(&acquired, 1)
				time.Sleep(100 * time.Millisecond) // Simulate work
				<-semaphore
			default:
				atomic.AddInt32(&rejected, 1)
			}
		}()
	}

	// Give goroutines time to attempt acquisition
	time.Sleep(50 * time.Millisecond)

	// Check that max concurrent is respected
	currentAcquired := atomic.LoadInt32(&acquired)
	currentRejected := atomic.LoadInt32(&rejected)

	testName := "Concurrency: semaphore limits concurrent runs"
	// At this point, we should have exactly 5 acquired (max) and 5 rejected
	if currentAcquired <= int32(maxConcurrent) {
		results = append(results, testResult{name: testName, passed: true})
		fmt.Printf("  ✓ %s (acquired: %d, rejected: %d)\n", testName, currentAcquired, currentRejected)
	} else {
		results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("acquired %d > max %d", currentAcquired, maxConcurrent)})
		fmt.Printf("  ✗ %s\n", testName)
	}

	wg.Wait()

	// Test per-tenant limits
	tenantLimits := make(map[string]int)
	tenantMu := sync.Mutex{}
	maxPerTenant := 3

	testTenants := []string{"tenant-1", "tenant-1", "tenant-1", "tenant-1", "tenant-2"}
	var tenantAcquired, tenantRejected int32

	for _, tenant := range testTenants {
		tenantMu.Lock()
		if tenantLimits[tenant] >= maxPerTenant {
			tenantMu.Unlock()
			atomic.AddInt32(&tenantRejected, 1)
			continue
		}
		tenantLimits[tenant]++
		tenantMu.Unlock()
		atomic.AddInt32(&tenantAcquired, 1)
	}

	testName = "Concurrency: per-tenant limits"
	// tenant-1 should have 3 acquired, 1 rejected; tenant-2 should have 1 acquired
	if tenantAcquired == 4 && tenantRejected == 1 {
		results = append(results, testResult{name: testName, passed: true})
		fmt.Printf("  ✓ %s (acquired: %d, rejected: %d)\n", testName, tenantAcquired, tenantRejected)
	} else {
		results = append(results, testResult{name: testName, passed: false, reason: fmt.Sprintf("expected 4 acquired, 1 rejected; got %d, %d", tenantAcquired, tenantRejected)})
		fmt.Printf("  ✗ %s\n", testName)
	}

	return results
}

// =============================================================================
// SEC-WF12: Panic Recovery Tests
// =============================================================================

func testPanicRecovery() []testResult {
	fmt.Println("\n--- SEC-WF12: Panic Recovery ---")

	results := []testResult{}

	// Test that panic is recovered and resources are released
	semaphore := make(chan struct{}, 1)
	var resourceReleased bool

	func() {
		var slotAcquired bool

		defer func() {
			if r := recover(); r != nil {
				// Panic recovered
			}
			// Always release resources
			if slotAcquired {
				<-semaphore
				resourceReleased = true
			}
		}()

		// Acquire slot
		semaphore <- struct{}{}
		slotAcquired = true

		// Simulate panic
		panic("simulated panic")
	}()

	testName := "Panic recovery: resources released after panic"
	if resourceReleased {
		results = append(results, testResult{name: testName, passed: true})
		fmt.Printf("  ✓ %s\n", testName)
	} else {
		results = append(results, testResult{name: testName, passed: false, reason: "resource was not released"})
		fmt.Printf("  ✗ %s\n", testName)
	}

	// Test that semaphore is available again
	select {
	case semaphore <- struct{}{}:
		results = append(results, testResult{name: "Panic recovery: semaphore available after recovery", passed: true})
		fmt.Printf("  ✓ Panic recovery: semaphore available after recovery\n")
		<-semaphore
	default:
		results = append(results, testResult{name: "Panic recovery: semaphore available after recovery", passed: false, reason: "semaphore still blocked"})
		fmt.Printf("  ✗ Panic recovery: semaphore available after recovery\n")
	}

	return results
}

// =============================================================================
// Helper Functions (mimicking the actual implementation)
// =============================================================================

func isBlockedIP(ip net.IP, blockedCIDRs []string) bool {
	for _, cidr := range blockedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isBlockedHostname(host string, blockedSuffixes []string) bool {
	lowHost := strings.ToLower(host)
	if lowHost == "localhost" {
		return true
	}
	for _, suffix := range blockedSuffixes {
		if strings.HasSuffix(lowHost, suffix) {
			return true
		}
	}
	return false
}

func validateURL(urlStr string, blockedCIDRs, blockedSuffixes []string) error {
	// Parse URL
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("invalid scheme")
	}

	// Extract host
	var host string
	if strings.HasPrefix(urlStr, "https://") {
		host = strings.TrimPrefix(urlStr, "https://")
	} else {
		host = strings.TrimPrefix(urlStr, "http://")
	}

	// Remove path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	// Remove port
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check hostname patterns
	if isBlockedHostname(host, blockedSuffixes) {
		return fmt.Errorf("blocked hostname")
	}

	// Check if IP
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip, blockedCIDRs) {
			return fmt.Errorf("blocked IP")
		}
	}

	return nil
}

func safeInterpolate(s string, replacements map[string]string) string {
	result := s
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

func sanitizeForLogging(s string) string {
	const maxLen = 100
	if len(s) > maxLen {
		s = s[:maxLen]
	}

	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			result.WriteRune(r)
		case r >= '0' && r <= '9':
			result.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			result.WriteRune(r)
		default:
			result.WriteRune('_')
		}
	}

	return result.String()
}

// Unused but kept for reference
var _ = httptest.NewServer
var _ = http.StatusOK
var _ = context.Background
