package unit

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Target Entity Tests
// =============================================================================

// TestNewTarget tests creating new scope targets.
//
// Run with: go test -v ./tests/unit -run TestNewTarget
func TestNewTarget(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("ValidDomainTarget", func(t *testing.T) {
		target, err := scope.NewTarget(tenantID, scope.TargetTypeDomain, "*.example.com", "Test domain", "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target.ID().IsZero() {
			t.Error("expected non-zero ID")
		}
		if target.TenantID() != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, target.TenantID())
		}
		if target.TargetType() != scope.TargetTypeDomain {
			t.Errorf("expected type domain, got %s", target.TargetType())
		}
		if target.Pattern() != "*.example.com" {
			t.Errorf("expected pattern *.example.com, got %s", target.Pattern())
		}
		if target.Description() != "Test domain" {
			t.Errorf("expected description 'Test domain', got %s", target.Description())
		}
		if target.Priority() != 0 {
			t.Errorf("expected priority 0, got %d", target.Priority())
		}
		if target.Status() != scope.StatusActive {
			t.Errorf("expected active status, got %s", target.Status())
		}
		if len(target.Tags()) != 0 {
			t.Errorf("expected empty tags, got %v", target.Tags())
		}
		if target.CreatedBy() != "user1" {
			t.Errorf("expected created_by user1, got %s", target.CreatedBy())
		}
		if target.CreatedAt().IsZero() {
			t.Error("expected non-zero created_at")
		}
		if !target.IsActive() {
			t.Error("expected target to be active")
		}
	})

	t.Run("ValidIPTarget", func(t *testing.T) {
		target, err := scope.NewTarget(tenantID, scope.TargetTypeIPAddress, "192.168.1.1", "", "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target.TargetType() != scope.TargetTypeIPAddress {
			t.Errorf("expected type ip_address, got %s", target.TargetType())
		}
	})

	t.Run("ValidCIDRTarget", func(t *testing.T) {
		target, err := scope.NewTarget(tenantID, scope.TargetTypeCIDR, "10.0.0.0/8", "", "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target.Pattern() != "10.0.0.0/8" {
			t.Errorf("expected pattern 10.0.0.0/8, got %s", target.Pattern())
		}
	})

	t.Run("ValidRepositoryTarget", func(t *testing.T) {
		target, err := scope.NewTarget(tenantID, scope.TargetTypeRepository, "github.com/org/repo", "", "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target.Pattern() != "github.com/org/repo" {
			t.Errorf("expected pattern github.com/org/repo, got %s", target.Pattern())
		}
	})

	t.Run("ValidURLTarget", func(t *testing.T) {
		target, err := scope.NewTarget(tenantID, scope.TargetTypeURL, "https://example.com/api/*", "", "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target.TargetType() != scope.TargetTypeURL {
			t.Errorf("expected type url, got %s", target.TargetType())
		}
	})

	t.Run("ValidCloudAccountTarget", func(t *testing.T) {
		target, err := scope.NewTarget(tenantID, scope.TargetTypeCloudAccount, "AWS:123456789012", "", "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target.Pattern() != "AWS:123456789012" {
			t.Errorf("expected pattern AWS:123456789012, got %s", target.Pattern())
		}
	})

	t.Run("ZeroTenantIDReturnsError", func(t *testing.T) {
		_, err := scope.NewTarget(shared.ID{}, scope.TargetTypeDomain, "example.com", "", "user1")
		if err == nil {
			t.Fatal("expected error for zero tenant ID")
		}
		if err != scope.ErrInvalidTenantID {
			t.Errorf("expected ErrInvalidTenantID, got %v", err)
		}
	})

	t.Run("InvalidTargetTypeReturnsError", func(t *testing.T) {
		_, err := scope.NewTarget(tenantID, scope.TargetType("invalid"), "example.com", "", "user1")
		if err == nil {
			t.Fatal("expected error for invalid target type")
		}
		if err != scope.ErrInvalidTargetType {
			t.Errorf("expected ErrInvalidTargetType, got %v", err)
		}
	})

	t.Run("EmptyPatternReturnsError", func(t *testing.T) {
		_, err := scope.NewTarget(tenantID, scope.TargetTypeDomain, "", "", "user1")
		if err == nil {
			t.Fatal("expected error for empty pattern")
		}
	})

	t.Run("InvalidDomainPatternReturnsError", func(t *testing.T) {
		_, err := scope.NewTarget(tenantID, scope.TargetTypeDomain, "not a valid domain!!!", "", "user1")
		if err == nil {
			t.Fatal("expected error for invalid domain pattern")
		}
	})

	t.Run("InvalidIPReturnsError", func(t *testing.T) {
		_, err := scope.NewTarget(tenantID, scope.TargetTypeIPAddress, "999.999.999.999", "", "user1")
		if err == nil {
			t.Fatal("expected error for invalid IP address")
		}
	})

	t.Run("InvalidCIDRReturnsError", func(t *testing.T) {
		_, err := scope.NewTarget(tenantID, scope.TargetTypeCIDR, "not-cidr", "", "user1")
		if err == nil {
			t.Fatal("expected error for invalid CIDR")
		}
	})
}

// TestTargetUpdateMethods tests Target entity update methods.
//
// Run with: go test -v ./tests/unit -run TestTargetUpdateMethods
func TestTargetUpdateMethods(t *testing.T) {
	tenantID := shared.NewID()
	target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "original", "user1")
	originalUpdatedAt := target.UpdatedAt()

	// Small delay to ensure timestamp changes
	time.Sleep(time.Millisecond)

	t.Run("UpdateDescription", func(t *testing.T) {
		target.UpdateDescription("updated description")
		if target.Description() != "updated description" {
			t.Errorf("expected 'updated description', got %s", target.Description())
		}
		if !target.UpdatedAt().After(originalUpdatedAt) {
			t.Error("expected updated_at to advance")
		}
	})

	t.Run("UpdatePriority", func(t *testing.T) {
		target.UpdatePriority(75)
		if target.Priority() != 75 {
			t.Errorf("expected priority 75, got %d", target.Priority())
		}
	})

	t.Run("UpdateTags", func(t *testing.T) {
		target.UpdateTags([]string{"production", "web"})
		if len(target.Tags()) != 2 {
			t.Errorf("expected 2 tags, got %d", len(target.Tags()))
		}
		if target.Tags()[0] != "production" || target.Tags()[1] != "web" {
			t.Errorf("expected [production web], got %v", target.Tags())
		}
	})

	t.Run("Deactivate", func(t *testing.T) {
		target.Deactivate()
		if target.Status() != scope.StatusInactive {
			t.Errorf("expected inactive, got %s", target.Status())
		}
		if target.IsActive() {
			t.Error("expected IsActive() to return false")
		}
	})

	t.Run("Activate", func(t *testing.T) {
		target.Activate()
		if target.Status() != scope.StatusActive {
			t.Errorf("expected active, got %s", target.Status())
		}
		if !target.IsActive() {
			t.Error("expected IsActive() to return true")
		}
	})
}

// TestReconstituteTarget tests recreating Target from persistence data.
//
// Run with: go test -v ./tests/unit -run TestReconstituteTarget
func TestReconstituteTarget(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	now := time.Now()

	target := scope.ReconstituteTarget(
		id, tenantID, scope.TargetTypeCIDR, "10.0.0.0/8", "desc", 50,
		scope.StatusActive, []string{"tag1"}, "user1", now, now,
	)

	if target.ID() != id {
		t.Errorf("expected ID %s, got %s", id, target.ID())
	}
	if target.Priority() != 50 {
		t.Errorf("expected priority 50, got %d", target.Priority())
	}
	if len(target.Tags()) != 1 || target.Tags()[0] != "tag1" {
		t.Errorf("expected [tag1], got %v", target.Tags())
	}
}

// =============================================================================
// Exclusion Entity Tests
// =============================================================================

// TestNewExclusion tests creating new scope exclusions.
//
// Run with: go test -v ./tests/unit -run TestNewExclusion
func TestNewExclusion(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("ValidExclusion", func(t *testing.T) {
		exc, err := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "internal.example.com", "Internal only", nil, "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if exc.ID().IsZero() {
			t.Error("expected non-zero ID")
		}
		if exc.ExclusionType() != scope.ExclusionTypeDomain {
			t.Errorf("expected type domain, got %s", exc.ExclusionType())
		}
		if exc.Pattern() != "internal.example.com" {
			t.Errorf("expected pattern internal.example.com, got %s", exc.Pattern())
		}
		if exc.Reason() != "Internal only" {
			t.Errorf("expected reason 'Internal only', got %s", exc.Reason())
		}
		if exc.Status() != scope.StatusActive {
			t.Errorf("expected active, got %s", exc.Status())
		}
		if exc.ExpiresAt() != nil {
			t.Error("expected nil ExpiresAt")
		}
		if exc.IsApproved() {
			t.Error("expected unapproved")
		}
		if !exc.IsActive() {
			t.Error("expected active")
		}
	})

	t.Run("WithExpiration", func(t *testing.T) {
		future := time.Now().Add(24 * time.Hour)
		exc, err := scope.NewExclusion(tenantID, scope.ExclusionTypeCIDR, "10.0.0.0/8", "Temp exclusion", &future, "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if exc.ExpiresAt() == nil {
			t.Fatal("expected non-nil ExpiresAt")
		}
		if !exc.IsActive() {
			t.Error("expected active (not yet expired)")
		}
	})

	t.Run("ZeroTenantIDReturnsError", func(t *testing.T) {
		_, err := scope.NewExclusion(shared.ID{}, scope.ExclusionTypeDomain, "example.com", "reason", nil, "user1")
		if err != scope.ErrInvalidTenantID {
			t.Errorf("expected ErrInvalidTenantID, got %v", err)
		}
	})

	t.Run("InvalidExclusionTypeReturnsError", func(t *testing.T) {
		_, err := scope.NewExclusion(tenantID, scope.ExclusionType("invalid"), "example.com", "reason", nil, "user1")
		if err != scope.ErrInvalidExclusionType {
			t.Errorf("expected ErrInvalidExclusionType, got %v", err)
		}
	})

	t.Run("EmptyReasonReturnsError", func(t *testing.T) {
		_, err := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "example.com", "", nil, "user1")
		if err != scope.ErrReasonRequired {
			t.Errorf("expected ErrReasonRequired, got %v", err)
		}
	})
}

// TestExclusionUpdateMethods tests Exclusion entity update methods.
//
// Run with: go test -v ./tests/unit -run TestExclusionUpdateMethods
func TestExclusionUpdateMethods(t *testing.T) {
	tenantID := shared.NewID()
	exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "original", nil, "user1")

	t.Run("UpdateReason", func(t *testing.T) {
		exc.UpdateReason("updated reason")
		if exc.Reason() != "updated reason" {
			t.Errorf("expected 'updated reason', got %s", exc.Reason())
		}
	})

	t.Run("UpdateExpiresAt", func(t *testing.T) {
		future := time.Now().Add(48 * time.Hour)
		exc.UpdateExpiresAt(&future)
		if exc.ExpiresAt() == nil {
			t.Fatal("expected non-nil ExpiresAt")
		}
	})

	t.Run("Approve", func(t *testing.T) {
		exc.Approve("admin1")
		if !exc.IsApproved() {
			t.Error("expected approved")
		}
		if exc.ApprovedBy() != "admin1" {
			t.Errorf("expected approved by admin1, got %s", exc.ApprovedBy())
		}
		if exc.ApprovedAt() == nil {
			t.Error("expected non-nil ApprovedAt")
		}
	})

	t.Run("Deactivate", func(t *testing.T) {
		exc.Deactivate()
		if exc.Status() != scope.StatusInactive {
			t.Errorf("expected inactive, got %s", exc.Status())
		}
		if exc.IsActive() {
			t.Error("expected IsActive() to return false")
		}
	})

	t.Run("Activate", func(t *testing.T) {
		exc.Activate()
		if exc.Status() != scope.StatusActive {
			t.Errorf("expected active, got %s", exc.Status())
		}
	})

	t.Run("MarkExpired", func(t *testing.T) {
		exc.MarkExpired()
		if exc.Status() != scope.StatusExpired {
			t.Errorf("expected expired, got %s", exc.Status())
		}
		if exc.IsActive() {
			t.Error("expected IsActive() to return false for expired")
		}
	})
}

// TestExclusionIsActive tests the IsActive logic with expiration.
//
// Run with: go test -v ./tests/unit -run TestExclusionIsActive
func TestExclusionIsActive(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("ActiveNoExpiry", func(t *testing.T) {
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		if !exc.IsActive() {
			t.Error("expected active (no expiry)")
		}
	})

	t.Run("ActiveFutureExpiry", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", &future, "user1")
		if !exc.IsActive() {
			t.Error("expected active (future expiry)")
		}
	})

	t.Run("InactiveExpiredByTime", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		id := shared.NewID()
		exc := scope.ReconstituteExclusion(
			id, tenantID, scope.ExclusionTypeDomain, "test.com", "reason",
			scope.StatusActive, &past, "", nil, "user1", time.Now(), time.Now(),
		)
		if exc.IsActive() {
			t.Error("expected inactive (past expiry)")
		}
	})

	t.Run("InactiveByStatus", func(t *testing.T) {
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		exc.Deactivate()
		if exc.IsActive() {
			t.Error("expected inactive (deactivated)")
		}
	})
}

// =============================================================================
// Schedule Entity Tests
// =============================================================================

// TestNewSchedule tests creating new scan schedules.
//
// Run with: go test -v ./tests/unit -run TestNewSchedule
func TestNewSchedule(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("ValidSchedule", func(t *testing.T) {
		sched, err := scope.NewSchedule(tenantID, "Daily Scan", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if sched.ID().IsZero() {
			t.Error("expected non-zero ID")
		}
		if sched.Name() != "Daily Scan" {
			t.Errorf("expected name 'Daily Scan', got %s", sched.Name())
		}
		if sched.ScanType() != scope.ScanTypeFull {
			t.Errorf("expected scan type full, got %s", sched.ScanType())
		}
		if sched.ScheduleType() != scope.ScheduleTypeCron {
			t.Errorf("expected schedule type cron, got %s", sched.ScheduleType())
		}
		if !sched.Enabled() {
			t.Error("expected enabled by default")
		}
		if sched.TargetScope() != scope.TargetScopeAll {
			t.Errorf("expected target scope all, got %s", sched.TargetScope())
		}
		if !sched.NotifyOnCompletion() {
			t.Error("expected notify on completion by default")
		}
		if !sched.NotifyOnFindings() {
			t.Error("expected notify on findings by default")
		}
		if len(sched.NotificationChannels()) != 1 || sched.NotificationChannels()[0] != "email" {
			t.Errorf("expected [email], got %v", sched.NotificationChannels())
		}
		if len(sched.TargetIDs()) != 0 {
			t.Errorf("expected empty target IDs, got %d", len(sched.TargetIDs()))
		}
		if len(sched.TargetTags()) != 0 {
			t.Errorf("expected empty target tags, got %d", len(sched.TargetTags()))
		}
		if sched.ScannerConfigs() == nil {
			t.Error("expected non-nil scanner configs")
		}
	})

	t.Run("ZeroTenantIDReturnsError", func(t *testing.T) {
		_, err := scope.NewSchedule(shared.ID{}, "Test", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
		if err != scope.ErrInvalidTenantID {
			t.Errorf("expected ErrInvalidTenantID, got %v", err)
		}
	})

	t.Run("EmptyNameReturnsError", func(t *testing.T) {
		_, err := scope.NewSchedule(tenantID, "", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
		if err != scope.ErrNameRequired {
			t.Errorf("expected ErrNameRequired, got %v", err)
		}
	})

	t.Run("InvalidScanTypeReturnsError", func(t *testing.T) {
		_, err := scope.NewSchedule(tenantID, "Test", scope.ScanType("invalid"), scope.ScheduleTypeCron, "user1")
		if err != scope.ErrInvalidScanType {
			t.Errorf("expected ErrInvalidScanType, got %v", err)
		}
	})

	t.Run("InvalidScheduleTypeReturnsError", func(t *testing.T) {
		_, err := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleType("invalid"), "user1")
		if err != scope.ErrInvalidScheduleType {
			t.Errorf("expected ErrInvalidScheduleType, got %v", err)
		}
	})
}

// TestScheduleUpdateMethods tests Schedule entity update methods.
//
// Run with: go test -v ./tests/unit -run TestScheduleUpdateMethods
func TestScheduleUpdateMethods(t *testing.T) {
	tenantID := shared.NewID()
	sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeManual, "user1")

	t.Run("UpdateName", func(t *testing.T) {
		sched.UpdateName("Updated Name")
		if sched.Name() != "Updated Name" {
			t.Errorf("expected 'Updated Name', got %s", sched.Name())
		}
	})

	t.Run("UpdateDescription", func(t *testing.T) {
		sched.UpdateDescription("Some description")
		if sched.Description() != "Some description" {
			t.Errorf("expected 'Some description', got %s", sched.Description())
		}
	})

	t.Run("SetCronSchedule", func(t *testing.T) {
		sched.SetCronSchedule("0 2 * * *")
		if sched.ScheduleType() != scope.ScheduleTypeCron {
			t.Errorf("expected cron, got %s", sched.ScheduleType())
		}
		if sched.CronExpression() != "0 2 * * *" {
			t.Errorf("expected '0 2 * * *', got %s", sched.CronExpression())
		}
		if sched.IntervalHours() != 0 {
			t.Errorf("expected interval 0, got %d", sched.IntervalHours())
		}
	})

	t.Run("SetIntervalSchedule", func(t *testing.T) {
		sched.SetIntervalSchedule(6)
		if sched.ScheduleType() != scope.ScheduleTypeInterval {
			t.Errorf("expected interval, got %s", sched.ScheduleType())
		}
		if sched.IntervalHours() != 6 {
			t.Errorf("expected 6 hours, got %d", sched.IntervalHours())
		}
		if sched.CronExpression() != "" {
			t.Errorf("expected empty cron, got %s", sched.CronExpression())
		}
	})

	t.Run("SetTargetScope", func(t *testing.T) {
		ids := []shared.ID{shared.NewID(), shared.NewID()}
		tags := []string{"web", "api"}
		sched.SetTargetScope(scope.TargetScopeSelected, ids, tags)
		if sched.TargetScope() != scope.TargetScopeSelected {
			t.Errorf("expected selected, got %s", sched.TargetScope())
		}
		if len(sched.TargetIDs()) != 2 {
			t.Errorf("expected 2 target IDs, got %d", len(sched.TargetIDs()))
		}
		if len(sched.TargetTags()) != 2 {
			t.Errorf("expected 2 tags, got %d", len(sched.TargetTags()))
		}
	})

	t.Run("UpdateScannerConfigs", func(t *testing.T) {
		configs := map[string]interface{}{"threads": 10, "timeout": "30s"}
		sched.UpdateScannerConfigs(configs)
		if len(sched.ScannerConfigs()) != 2 {
			t.Errorf("expected 2 config entries, got %d", len(sched.ScannerConfigs()))
		}
	})

	t.Run("Disable", func(t *testing.T) {
		sched.Disable()
		if sched.Enabled() {
			t.Error("expected disabled")
		}
	})

	t.Run("Enable", func(t *testing.T) {
		sched.Enable()
		if !sched.Enabled() {
			t.Error("expected enabled")
		}
	})

	t.Run("RecordRun", func(t *testing.T) {
		next := time.Now().Add(6 * time.Hour)
		sched.RecordRun("completed", &next)
		if sched.LastRunAt() == nil {
			t.Error("expected non-nil LastRunAt")
		}
		if sched.LastRunStatus() != "completed" {
			t.Errorf("expected status 'completed', got %s", sched.LastRunStatus())
		}
		if sched.NextRunAt() == nil {
			t.Error("expected non-nil NextRunAt")
		}
	})

	t.Run("UpdateNotifications", func(t *testing.T) {
		sched.UpdateNotifications(false, true, []string{"slack", "email"})
		if sched.NotifyOnCompletion() {
			t.Error("expected no completion notification")
		}
		if !sched.NotifyOnFindings() {
			t.Error("expected findings notification")
		}
		if len(sched.NotificationChannels()) != 2 {
			t.Errorf("expected 2 channels, got %d", len(sched.NotificationChannels()))
		}
	})
}

// =============================================================================
// Value Object Tests
// =============================================================================

// TestTargetTypeIsValid tests TargetType validation.
//
// Run with: go test -v ./tests/unit -run TestTargetTypeIsValid
func TestTargetTypeIsValid(t *testing.T) {
	validTypes := []scope.TargetType{
		scope.TargetTypeDomain, scope.TargetTypeSubdomain, scope.TargetTypeIPAddress,
		scope.TargetTypeIPRange, scope.TargetTypeCIDR, scope.TargetTypeURL,
		scope.TargetTypeAPI, scope.TargetTypeWebsite, scope.TargetTypeRepository,
		scope.TargetTypeProject, scope.TargetTypeCloudAccount, scope.TargetTypeCloudResource,
		scope.TargetTypeContainer, scope.TargetTypeHost, scope.TargetTypeDatabase,
		scope.TargetTypeNetwork, scope.TargetTypeCertificate, scope.TargetTypeMobileApp,
		scope.TargetTypeEmailDomain,
	}

	for _, tt := range validTypes {
		t.Run("Valid_"+tt.String(), func(t *testing.T) {
			if !tt.IsValid() {
				t.Errorf("expected %s to be valid", tt)
			}
		})
	}

	invalidTypes := []scope.TargetType{"invalid", "", "DOMAIN", "unknown"}
	for _, tt := range invalidTypes {
		t.Run("Invalid_"+string(tt), func(t *testing.T) {
			if tt.IsValid() {
				t.Errorf("expected %s to be invalid", tt)
			}
		})
	}
}

// TestParseTargetType tests parsing target type strings.
//
// Run with: go test -v ./tests/unit -run TestParseTargetType
func TestParseTargetType(t *testing.T) {
	t.Run("ValidLowercase", func(t *testing.T) {
		tt, err := scope.ParseTargetType("domain")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if tt != scope.TargetTypeDomain {
			t.Errorf("expected domain, got %s", tt)
		}
	})

	t.Run("ValidUppercase", func(t *testing.T) {
		tt, err := scope.ParseTargetType("CIDR")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if tt != scope.TargetTypeCIDR {
			t.Errorf("expected cidr, got %s", tt)
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		_, err := scope.ParseTargetType("not_a_type")
		if err == nil {
			t.Fatal("expected error for invalid type")
		}
	})
}

// TestExclusionTypeIsValid tests ExclusionType validation.
//
// Run with: go test -v ./tests/unit -run TestExclusionTypeIsValid
func TestExclusionTypeIsValid(t *testing.T) {
	validTypes := []scope.ExclusionType{
		scope.ExclusionTypeDomain, scope.ExclusionTypeSubdomain, scope.ExclusionTypeIPAddress,
		scope.ExclusionTypeIPRange, scope.ExclusionTypeCIDR, scope.ExclusionTypeURL,
		scope.ExclusionTypePath, scope.ExclusionTypeRepository, scope.ExclusionTypeFindingType,
		scope.ExclusionTypeScanner,
	}

	for _, et := range validTypes {
		if !et.IsValid() {
			t.Errorf("expected %s to be valid", et)
		}
	}

	if scope.ExclusionType("invalid").IsValid() {
		t.Error("expected 'invalid' to be invalid")
	}
}

// TestStatusIsValid tests Status validation.
//
// Run with: go test -v ./tests/unit -run TestStatusIsValid
func TestStatusIsValid(t *testing.T) {
	if !scope.StatusActive.IsValid() {
		t.Error("active should be valid")
	}
	if !scope.StatusInactive.IsValid() {
		t.Error("inactive should be valid")
	}
	if !scope.StatusExpired.IsValid() {
		t.Error("expired should be valid")
	}
	if scope.Status("unknown").IsValid() {
		t.Error("unknown should be invalid")
	}
}

// TestScanTypeIsValid tests ScanType validation.
//
// Run with: go test -v ./tests/unit -run TestScanTypeIsValid
func TestScanTypeIsValid(t *testing.T) {
	validScanTypes := []scope.ScanType{
		scope.ScanTypeFull, scope.ScanTypeIncremental, scope.ScanTypeTargeted,
		scope.ScanTypeVulnerability, scope.ScanTypeCompliance, scope.ScanTypeSecret,
		scope.ScanTypeSAST, scope.ScanTypeDAST, scope.ScanTypeSCA,
	}

	for _, st := range validScanTypes {
		if !st.IsValid() {
			t.Errorf("expected %s to be valid", st)
		}
	}

	if scope.ScanType("invalid").IsValid() {
		t.Error("expected 'invalid' to be invalid scan type")
	}
}

// TestScheduleTypeIsValid tests ScheduleType validation.
//
// Run with: go test -v ./tests/unit -run TestScheduleTypeIsValid
func TestScheduleTypeIsValid(t *testing.T) {
	if !scope.ScheduleTypeCron.IsValid() {
		t.Error("cron should be valid")
	}
	if !scope.ScheduleTypeInterval.IsValid() {
		t.Error("interval should be valid")
	}
	if !scope.ScheduleTypeManual.IsValid() {
		t.Error("manual should be valid")
	}
	if scope.ScheduleType("hourly").IsValid() {
		t.Error("hourly should be invalid")
	}
}

// =============================================================================
// Pattern Validation Tests
// =============================================================================

// TestValidatePattern tests pattern validation for various target types.
//
// Run with: go test -v ./tests/unit -run TestValidatePattern
func TestValidatePattern(t *testing.T) {
	tests := []struct {
		name       string
		targetType scope.TargetType
		pattern    string
		wantErr    bool
	}{
		// Domain patterns
		{"DomainExact", scope.TargetTypeDomain, "example.com", false},
		{"DomainWildcard", scope.TargetTypeDomain, "*.example.com", false},
		{"DomainDoubleWildcard", scope.TargetTypeDomain, "**.example.com", false},
		{"DomainSubdomain", scope.TargetTypeSubdomain, "sub.example.com", false},
		{"DomainInvalid", scope.TargetTypeDomain, "not a domain!!!", true},
		{"DomainEmpty", scope.TargetTypeDomain, "", true},

		// IP patterns
		{"IPv4Valid", scope.TargetTypeIPAddress, "192.168.1.1", false},
		{"IPv6Valid", scope.TargetTypeIPAddress, "::1", false},
		{"IPv4Invalid", scope.TargetTypeIPAddress, "999.999.999.999", true},

		// CIDR patterns
		{"CIDR24", scope.TargetTypeCIDR, "10.0.0.0/24", false},
		{"CIDR8", scope.TargetTypeCIDR, "10.0.0.0/8", false},
		{"CIDRv6", scope.TargetTypeCIDR, "fd00::/8", false},
		{"IPRange", scope.TargetTypeIPRange, "192.168.1.1-192.168.1.254", false},
		{"CIDRInvalid", scope.TargetTypeCIDR, "not-cidr", true},

		// Repository patterns
		{"RepoFull", scope.TargetTypeRepository, "github.com/org/repo", false},
		{"RepoWildcard", scope.TargetTypeRepository, "github.com/org/*", false},
		{"RepoInvalid", scope.TargetTypeRepository, "not a repo", true},

		// Cloud account patterns
		{"CloudAWS", scope.TargetTypeCloudAccount, "AWS:123456789012", false},
		{"CloudGCP", scope.TargetTypeCloudAccount, "GCP:my-project", false},
		{"CloudAzure", scope.TargetTypeCloudAccount, "Azure:sub-id", false},
		{"CloudInvalid", scope.TargetTypeCloudAccount, "invalid-format", true},

		// URL patterns
		{"URLHttps", scope.TargetTypeURL, "https://example.com", false},
		{"URLHttp", scope.TargetTypeURL, "http://example.com/api", false},
		{"URLWildcard", scope.TargetTypeURL, "*://example.com", false},
		{"URLInvalid", scope.TargetTypeURL, "not-a-url", true},

		// Generic types (no strict validation)
		{"ContainerGeneric", scope.TargetTypeContainer, "my-container:latest", false},
		{"HostGeneric", scope.TargetTypeHost, "server-01", false},
		{"DatabaseGeneric", scope.TargetTypeDatabase, "production-db", false},

		// Too long pattern
		{"PatternTooLong", scope.TargetTypeDomain, string(make([]byte, 501)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scope.ValidatePattern(tt.targetType, tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePattern(%s, %q) error = %v, wantErr = %v", tt.targetType, tt.pattern, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Pattern Matching Tests
// =============================================================================

// TestMatchesPatternDomain tests domain pattern matching.
//
// Run with: go test -v ./tests/unit -run TestMatchesPatternDomain
func TestMatchesPatternDomain(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"ExactMatch", "example.com", "example.com", true},
		{"ExactMatchCaseInsensitive", "Example.COM", "example.com", true},
		{"NoMatch", "example.com", "other.com", false},
		{"WildcardMatchSubdomain", "*.example.com", "sub.example.com", true},
		{"WildcardMatchDeepSubdomain", "*.example.com", "deep.sub.example.com", true},
		{"WildcardMatchRootDomain", "*.example.com", "example.com", true},
		{"WildcardNoMatch", "*.example.com", "other.com", false},
		{"DoubleWildcardMatch", "**.example.com", "a.b.c.example.com", true},
		{"DoubleWildcardMatchRoot", "**.example.com", "example.com", true},
		{"DoubleWildcardNoMatch", "**.example.com", "notexample.com", false},
		{"SubdomainType", "*.test.org", "api.test.org", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scope.MatchesPattern(scope.TargetTypeDomain, tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchesPattern(domain, %q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestMatchesPatternIP tests IP address pattern matching.
//
// Run with: go test -v ./tests/unit -run TestMatchesPatternIP
func TestMatchesPatternIP(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"ExactMatch", "192.168.1.1", "192.168.1.1", true},
		{"NoMatch", "192.168.1.1", "192.168.1.2", false},
		{"IPv6ExactMatch", "::1", "::1", true},
		{"IPv6NoMatch", "::1", "::2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scope.MatchesPattern(scope.TargetTypeIPAddress, tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchesPattern(ip_address, %q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestMatchesPatternCIDR tests CIDR and IP range pattern matching.
//
// Run with: go test -v ./tests/unit -run TestMatchesPatternCIDR
func TestMatchesPatternCIDR(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// CIDR matching
		{"CIDRContains", "192.168.1.0/24", "192.168.1.100", true},
		{"CIDRContainsFirst", "192.168.1.0/24", "192.168.1.0", true},
		{"CIDRContainsLast", "192.168.1.0/24", "192.168.1.255", true},
		{"CIDROutOfRange", "192.168.1.0/24", "192.168.2.1", false},
		{"CIDRLargeRange", "10.0.0.0/8", "10.255.255.255", true},
		{"CIDRLargeRangeOutside", "10.0.0.0/8", "11.0.0.1", false},
		{"CIDR16", "172.16.0.0/16", "172.16.50.50", true},
		{"CIDR16Outside", "172.16.0.0/16", "172.17.0.1", false},

		// IPv6 CIDR
		{"IPv6CIDRContains", "fd00::/8", "fd00::1", true},
		{"IPv6CIDROutside", "fd00::/16", "fe00::1", false},

		// IP range
		{"RangeContains", "192.168.1.1-192.168.1.10", "192.168.1.5", true},
		{"RangeStart", "192.168.1.1-192.168.1.10", "192.168.1.1", true},
		{"RangeEnd", "192.168.1.1-192.168.1.10", "192.168.1.10", true},
		{"RangeOutside", "192.168.1.1-192.168.1.10", "192.168.1.11", false},

		// Invalid value (not an IP)
		{"InvalidValue", "192.168.1.0/24", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scope.MatchesPattern(scope.TargetTypeCIDR, tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchesPattern(cidr, %q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestMatchesPatternWildcard tests wildcard pattern matching for repositories, URLs, etc.
//
// Run with: go test -v ./tests/unit -run TestMatchesPatternWildcard
func TestMatchesPatternWildcard(t *testing.T) {
	tests := []struct {
		name       string
		targetType scope.TargetType
		pattern    string
		value      string
		want       bool
	}{
		// Repository matching
		{"RepoExact", scope.TargetTypeRepository, "github.com/org/repo", "github.com/org/repo", true},
		{"RepoWildcard", scope.TargetTypeRepository, "github.com/org/*", "github.com/org/any-repo", true},
		{"RepoWildcardRoot", scope.TargetTypeRepository, "github.com/org/*", "github.com/org", true},
		{"RepoWildcardNoMatch", scope.TargetTypeRepository, "github.com/org/*", "github.com/other/repo", false},
		{"RepoCaseInsensitive", scope.TargetTypeRepository, "GitHub.com/Org/Repo", "github.com/org/repo", true},

		// Cloud account matching
		{"CloudExact", scope.TargetTypeCloudAccount, "AWS:123456789012", "AWS:123456789012", true},
		{"CloudWildcard", scope.TargetTypeCloudAccount, "AWS:*", "AWS:123456789012", true},
		{"CloudNoMatch", scope.TargetTypeCloudAccount, "AWS:123", "GCP:123", false},

		// Default wildcard matching (host, container, etc.)
		{"HostExact", scope.TargetTypeHost, "server-01", "server-01", true},
		{"HostWildcard", scope.TargetTypeHost, "server-*", "server-01", true},
		{"HostNoMatch", scope.TargetTypeHost, "server-01", "server-02", false},

		// Middle wildcard
		{"MiddleWildcard", scope.TargetTypeHost, "prod-*-web", "prod-east-web", true},
		{"MiddleWildcardNoMatch", scope.TargetTypeHost, "prod-*-web", "prod-east-api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scope.MatchesPattern(tt.targetType, tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchesPattern(%s, %q, %q) = %v, want %v", tt.targetType, tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestTargetMatches tests the Target.Matches convenience method.
//
// Run with: go test -v ./tests/unit -run TestTargetMatches
func TestTargetMatches(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("DomainTargetMatches", func(t *testing.T) {
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "*.example.com", "", "user1")
		if !target.Matches("sub.example.com") {
			t.Error("expected match for sub.example.com")
		}
		if target.Matches("other.com") {
			t.Error("expected no match for other.com")
		}
	})

	t.Run("ExclusionMatches", func(t *testing.T) {
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "*.internal.com", "Internal", nil, "user1")
		if !exc.Matches("api.internal.com") {
			t.Error("expected match for api.internal.com")
		}
		if exc.Matches("external.com") {
			t.Error("expected no match for external.com")
		}
	})
}

// TestAllTargetTypes tests that AllTargetTypes returns all valid types.
//
// Run with: go test -v ./tests/unit -run TestAllTargetTypes
func TestAllTargetTypes(t *testing.T) {
	allTypes := scope.AllTargetTypes()
	if len(allTypes) != 19 {
		t.Errorf("expected 19 target types, got %d", len(allTypes))
	}

	for _, tt := range allTypes {
		if !tt.IsValid() {
			t.Errorf("AllTargetTypes() returned invalid type: %s", tt)
		}
	}
}

// TestParseExclusionType tests parsing exclusion type strings.
//
// Run with: go test -v ./tests/unit -run TestParseExclusionType
func TestParseExclusionType(t *testing.T) {
	t.Run("ValidLowercase", func(t *testing.T) {
		et, err := scope.ParseExclusionType("domain")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if et != scope.ExclusionTypeDomain {
			t.Errorf("expected domain, got %s", et)
		}
	})

	t.Run("ValidUppercase", func(t *testing.T) {
		et, err := scope.ParseExclusionType("IP_ADDRESS")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if et != scope.ExclusionTypeIPAddress {
			t.Errorf("expected ip_address, got %s", et)
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		_, err := scope.ParseExclusionType("not_a_type")
		if err == nil {
			t.Fatal("expected error for invalid type")
		}
	})
}

// TestParseScanType tests parsing scan type strings.
//
// Run with: go test -v ./tests/unit -run TestParseScanType
func TestParseScanType(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		st, err := scope.ParseScanType("full")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if st != scope.ScanTypeFull {
			t.Errorf("expected full, got %s", st)
		}
	})

	t.Run("ValidUppercase", func(t *testing.T) {
		st, err := scope.ParseScanType("SAST")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if st != scope.ScanTypeSAST {
			t.Errorf("expected sast, got %s", st)
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		_, err := scope.ParseScanType("invalid")
		if err == nil {
			t.Fatal("expected error for invalid scan type")
		}
	})
}

// TestReconstituteSchedule tests recreating Schedule from persistence data.
//
// Run with: go test -v ./tests/unit -run TestReconstituteSchedule
func TestReconstituteSchedule(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	targetIDs := []shared.ID{shared.NewID()}
	now := time.Now()
	nextRun := now.Add(time.Hour)
	configs := map[string]interface{}{"key": "value"}

	sched := scope.ReconstituteSchedule(
		id, tenantID, "Test Schedule", "desc",
		scope.ScanTypeFull, scope.TargetScopeSelected, targetIDs, []string{"tag1"},
		configs, scope.ScheduleTypeCron, "0 */6 * * *", 0,
		true, &now, "completed", &nextRun,
		true, true, []string{"slack"}, "user1", now, now,
	)

	if sched.ID() != id {
		t.Errorf("expected ID %s, got %s", id, sched.ID())
	}
	if sched.Name() != "Test Schedule" {
		t.Errorf("expected 'Test Schedule', got %s", sched.Name())
	}
	if sched.Description() != "desc" {
		t.Errorf("expected 'desc', got %s", sched.Description())
	}
	if sched.TargetScope() != scope.TargetScopeSelected {
		t.Errorf("expected selected, got %s", sched.TargetScope())
	}
	if len(sched.TargetIDs()) != 1 {
		t.Errorf("expected 1 target ID, got %d", len(sched.TargetIDs()))
	}
	if sched.CronExpression() != "0 */6 * * *" {
		t.Errorf("expected '0 */6 * * *', got %s", sched.CronExpression())
	}
	if sched.LastRunStatus() != "completed" {
		t.Errorf("expected 'completed', got %s", sched.LastRunStatus())
	}
	if len(sched.NotificationChannels()) != 1 || sched.NotificationChannels()[0] != "slack" {
		t.Errorf("expected [slack], got %v", sched.NotificationChannels())
	}
	if sched.ScannerConfigs()["key"] != "value" {
		t.Errorf("expected config key=value, got %v", sched.ScannerConfigs())
	}
}
