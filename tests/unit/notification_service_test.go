package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Notification Repository
// =============================================================================

type mockNotificationRepo struct {
	// Storage
	notifications map[shared.ID]*notification.Notification
	preferences   map[string]*notification.Preferences // key: "tenantID:userID"
	readStatus    map[string]bool                      // key: "tenantID:notifID:userID"
	allReadAt     map[string]time.Time                 // key: "tenantID:userID"

	// Error overrides
	createErr          error
	listErr            error
	unreadCountErr     error
	markAsReadErr      error
	markAllAsReadErr   error
	deleteOlderErr     error
	getPreferencesErr  error
	upsertPrefsErr     error

	// Call tracking
	createCalls        int
	listCalls          int
	unreadCountCalls   int
	markAsReadCalls    int
	markAllAsReadCalls int
	deleteOlderCalls   int
	getPrefsCalls      int
	upsertPrefsCalls   int

	// Captured arguments
	lastFilter     notification.ListFilter
	lastPagination pagination.Pagination
	lastDeleteAge  time.Duration

	// Return overrides
	unreadCountResult  int
	deleteOlderResult  int64
	upsertPrefsResult  *notification.Preferences
}

func newMockNotificationRepo() *mockNotificationRepo {
	return &mockNotificationRepo{
		notifications: make(map[shared.ID]*notification.Notification),
		preferences:   make(map[string]*notification.Preferences),
		readStatus:    make(map[string]bool),
		allReadAt:     make(map[string]time.Time),
	}
}

func (m *mockNotificationRepo) Create(_ context.Context, n *notification.Notification) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.notifications[n.ID()] = n
	return nil
}

func (m *mockNotificationRepo) List(_ context.Context, tenantID, userID shared.ID, filter notification.ListFilter, page pagination.Pagination) (pagination.Result[*notification.Notification], error) {
	m.listCalls++
	m.lastFilter = filter
	m.lastPagination = page
	if m.listErr != nil {
		return pagination.Result[*notification.Notification]{}, m.listErr
	}
	items := make([]*notification.Notification, 0, len(m.notifications))
	for _, n := range m.notifications {
		if n.TenantID().Equals(tenantID) {
			items = append(items, n)
		}
	}
	return pagination.Result[*notification.Notification]{
		Data:       items,
		Total:      int64(len(items)),
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *mockNotificationRepo) UnreadCount(_ context.Context, _, _ shared.ID) (int, error) {
	m.unreadCountCalls++
	if m.unreadCountErr != nil {
		return 0, m.unreadCountErr
	}
	return m.unreadCountResult, nil
}

func (m *mockNotificationRepo) MarkAsRead(_ context.Context, tenantID shared.ID, notificationID notification.ID, userID shared.ID) error {
	m.markAsReadCalls++
	if m.markAsReadErr != nil {
		return m.markAsReadErr
	}
	key := fmt.Sprintf("%s:%s:%s", tenantID, notificationID, userID)
	m.readStatus[key] = true
	return nil
}

func (m *mockNotificationRepo) MarkAllAsRead(_ context.Context, tenantID, userID shared.ID) error {
	m.markAllAsReadCalls++
	if m.markAllAsReadErr != nil {
		return m.markAllAsReadErr
	}
	key := fmt.Sprintf("%s:%s", tenantID, userID)
	m.allReadAt[key] = time.Now()
	return nil
}

func (m *mockNotificationRepo) DeleteOlderThan(_ context.Context, age time.Duration) (int64, error) {
	m.deleteOlderCalls++
	m.lastDeleteAge = age
	if m.deleteOlderErr != nil {
		return 0, m.deleteOlderErr
	}
	return m.deleteOlderResult, nil
}

func (m *mockNotificationRepo) GetPreferences(_ context.Context, tenantID, userID shared.ID) (*notification.Preferences, error) {
	m.getPrefsCalls++
	if m.getPreferencesErr != nil {
		return nil, m.getPreferencesErr
	}
	key := fmt.Sprintf("%s:%s", tenantID, userID)
	if prefs, ok := m.preferences[key]; ok {
		return prefs, nil
	}
	return notification.DefaultPreferences(tenantID, userID), nil
}

func (m *mockNotificationRepo) UpsertPreferences(_ context.Context, tenantID, userID shared.ID, params notification.PreferencesParams) (*notification.Preferences, error) {
	m.upsertPrefsCalls++
	if m.upsertPrefsErr != nil {
		return nil, m.upsertPrefsErr
	}
	if m.upsertPrefsResult != nil {
		return m.upsertPrefsResult, nil
	}
	prefs := notification.ReconstitutePref(
		tenantID, userID,
		params.InAppEnabled,
		params.EmailDigest,
		params.MutedTypes,
		params.MinSeverity,
		time.Now(),
	)
	key := fmt.Sprintf("%s:%s", tenantID, userID)
	m.preferences[key] = prefs
	return prefs, nil
}

// =============================================================================
// Mock WebSocket Broadcaster
// =============================================================================

type wsBroadcastCall struct {
	channel  string
	data     interface{}
	tenantID string
}

type mockWSBroadcaster struct {
	calls []wsBroadcastCall
}

func newMockWSBroadcaster() *mockWSBroadcaster {
	return &mockWSBroadcaster{
		calls: make([]wsBroadcastCall, 0),
	}
}

func (m *mockWSBroadcaster) BroadcastEvent(channel string, data interface{}, tenantID string) {
	m.calls = append(m.calls, wsBroadcastCall{
		channel:  channel,
		data:     data,
		tenantID: tenantID,
	})
}

// =============================================================================
// Helper: Create NotificationService
// =============================================================================

func newTestNotificationService(repo notification.Repository, ws app.WebSocketBroadcaster) *app.NotificationService {
	log := logger.NewNop()
	return app.NewNotificationService(repo, ws, log)
}

// =============================================================================
// 1. Domain Entity Tests
// =============================================================================

func TestNewNotification(t *testing.T) {
	tenantID := shared.NewID()
	audienceID := shared.NewID()
	resourceID := shared.NewID()
	actorID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceUser,
		AudienceID:       &audienceID,
		NotificationType: notification.TypeFindingNew,
		Title:            "New Finding",
		Body:             "A critical finding was detected",
		Severity:         notification.SeverityCritical,
		ResourceType:     "finding",
		ResourceID:       &resourceID,
		URL:              "/findings/123",
		ActorID:          &actorID,
	}

	n := notification.NewNotification(params)

	if n.ID().IsZero() {
		t.Fatal("expected non-zero ID")
	}
	if !n.TenantID().Equals(tenantID) {
		t.Errorf("expected tenantID %s, got %s", tenantID, n.TenantID())
	}
	if n.Audience() != notification.AudienceUser {
		t.Errorf("expected audience %s, got %s", notification.AudienceUser, n.Audience())
	}
	if n.AudienceID() == nil || !n.AudienceID().Equals(audienceID) {
		t.Errorf("expected audienceID %s, got %v", audienceID, n.AudienceID())
	}
	if n.NotificationType() != notification.TypeFindingNew {
		t.Errorf("expected type %s, got %s", notification.TypeFindingNew, n.NotificationType())
	}
	if n.Title() != "New Finding" {
		t.Errorf("expected title 'New Finding', got %s", n.Title())
	}
	if n.Body() != "A critical finding was detected" {
		t.Errorf("expected body 'A critical finding was detected', got %s", n.Body())
	}
	if n.Severity() != notification.SeverityCritical {
		t.Errorf("expected severity %s, got %s", notification.SeverityCritical, n.Severity())
	}
	if n.ResourceType() != "finding" {
		t.Errorf("expected resource type 'finding', got %s", n.ResourceType())
	}
	if n.ResourceID() == nil || !n.ResourceID().Equals(resourceID) {
		t.Errorf("expected resourceID %s, got %v", resourceID, n.ResourceID())
	}
	if n.URL() != "/findings/123" {
		t.Errorf("expected URL '/findings/123', got %s", n.URL())
	}
	if n.ActorID() == nil || !n.ActorID().Equals(actorID) {
		t.Errorf("expected actorID %s, got %v", actorID, n.ActorID())
	}
	if n.CreatedAt().IsZero() {
		t.Fatal("expected non-zero createdAt")
	}
	if n.IsRead() {
		t.Error("expected isRead to be false for new notification")
	}
}

func TestNewNotification_OptionalFields(t *testing.T) {
	tenantID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceAll,
		AudienceID:       nil,
		NotificationType: notification.TypeSystemAlert,
		Title:            "System Alert",
		Body:             "Scheduled maintenance",
		Severity:         notification.SeverityInfo,
		ResourceType:     "",
		ResourceID:       nil,
		URL:              "",
		ActorID:          nil,
	}

	n := notification.NewNotification(params)

	if n.AudienceID() != nil {
		t.Errorf("expected nil audienceID, got %v", n.AudienceID())
	}
	if n.ResourceID() != nil {
		t.Errorf("expected nil resourceID, got %v", n.ResourceID())
	}
	if n.ActorID() != nil {
		t.Errorf("expected nil actorID, got %v", n.ActorID())
	}
	if n.ResourceType() != "" {
		t.Errorf("expected empty resource type, got %s", n.ResourceType())
	}
	if n.URL() != "" {
		t.Errorf("expected empty URL, got %s", n.URL())
	}
}

func TestReconstitute(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	audienceID := shared.NewID()
	resourceID := shared.NewID()
	actorID := shared.NewID()
	createdAt := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)

	n := notification.Reconstitute(
		id, tenantID, notification.AudienceGroup, &audienceID,
		notification.TypeScanCompleted, "Scan Done", "Scan finished successfully",
		notification.SeverityMedium, "scan", &resourceID, "/scans/456",
		&actorID, createdAt, true,
	)

	if !n.ID().Equals(id) {
		t.Errorf("expected ID %s, got %s", id, n.ID())
	}
	if !n.TenantID().Equals(tenantID) {
		t.Errorf("expected tenantID %s, got %s", tenantID, n.TenantID())
	}
	if n.Audience() != notification.AudienceGroup {
		t.Errorf("expected audience group, got %s", n.Audience())
	}
	if !n.AudienceID().Equals(audienceID) {
		t.Errorf("expected audienceID %s, got %v", audienceID, n.AudienceID())
	}
	if n.NotificationType() != notification.TypeScanCompleted {
		t.Errorf("expected type %s, got %s", notification.TypeScanCompleted, n.NotificationType())
	}
	if n.Title() != "Scan Done" {
		t.Errorf("expected title 'Scan Done', got %s", n.Title())
	}
	if n.Body() != "Scan finished successfully" {
		t.Errorf("expected body 'Scan finished successfully', got %s", n.Body())
	}
	if n.Severity() != notification.SeverityMedium {
		t.Errorf("expected severity %s, got %s", notification.SeverityMedium, n.Severity())
	}
	if n.ResourceType() != "scan" {
		t.Errorf("expected resource type 'scan', got %s", n.ResourceType())
	}
	if !n.ResourceID().Equals(resourceID) {
		t.Errorf("expected resourceID %s, got %v", resourceID, n.ResourceID())
	}
	if n.URL() != "/scans/456" {
		t.Errorf("expected URL '/scans/456', got %s", n.URL())
	}
	if !n.ActorID().Equals(actorID) {
		t.Errorf("expected actorID %s, got %v", actorID, n.ActorID())
	}
	if !n.CreatedAt().Equal(createdAt) {
		t.Errorf("expected createdAt %v, got %v", createdAt, n.CreatedAt())
	}
	if !n.IsRead() {
		t.Error("expected isRead to be true")
	}
}

func TestDefaultPreferences(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	prefs := notification.DefaultPreferences(tenantID, userID)

	if !prefs.TenantID().Equals(tenantID) {
		t.Errorf("expected tenantID %s, got %s", tenantID, prefs.TenantID())
	}
	if !prefs.UserID().Equals(userID) {
		t.Errorf("expected userID %s, got %s", userID, prefs.UserID())
	}
	if !prefs.InAppEnabled() {
		t.Error("expected inAppEnabled to be true")
	}
	if prefs.EmailDigest() != "none" {
		t.Errorf("expected emailDigest 'none', got %s", prefs.EmailDigest())
	}
	if len(prefs.MutedTypes()) != 0 {
		t.Errorf("expected empty mutedTypes, got %v", prefs.MutedTypes())
	}
	if prefs.MinSeverity() != "" {
		t.Errorf("expected empty minSeverity, got %s", prefs.MinSeverity())
	}
	if prefs.UpdatedAt().IsZero() {
		t.Error("expected non-zero updatedAt")
	}
}

func TestReconstitutePref(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()
	updatedAt := time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)
	mutedTypes := []string{notification.TypeMemberJoined, notification.TypeRoleChanged}

	prefs := notification.ReconstitutePref(
		tenantID, userID,
		false, "daily", mutedTypes, notification.SeverityHigh, updatedAt,
	)

	if !prefs.TenantID().Equals(tenantID) {
		t.Errorf("expected tenantID %s, got %s", tenantID, prefs.TenantID())
	}
	if !prefs.UserID().Equals(userID) {
		t.Errorf("expected userID %s, got %s", userID, prefs.UserID())
	}
	if prefs.InAppEnabled() {
		t.Error("expected inAppEnabled to be false")
	}
	if prefs.EmailDigest() != "daily" {
		t.Errorf("expected emailDigest 'daily', got %s", prefs.EmailDigest())
	}
	if len(prefs.MutedTypes()) != 2 {
		t.Fatalf("expected 2 muted types, got %d", len(prefs.MutedTypes()))
	}
	if prefs.MutedTypes()[0] != notification.TypeMemberJoined {
		t.Errorf("expected muted type %s, got %s", notification.TypeMemberJoined, prefs.MutedTypes()[0])
	}
	if prefs.MinSeverity() != notification.SeverityHigh {
		t.Errorf("expected minSeverity %s, got %s", notification.SeverityHigh, prefs.MinSeverity())
	}
	if !prefs.UpdatedAt().Equal(updatedAt) {
		t.Errorf("expected updatedAt %v, got %v", updatedAt, prefs.UpdatedAt())
	}
}

func TestIsValidSeverity(t *testing.T) {
	validSeverities := []string{
		notification.SeverityCritical,
		notification.SeverityHigh,
		notification.SeverityMedium,
		notification.SeverityLow,
		notification.SeverityInfo,
	}
	for _, s := range validSeverities {
		if !notification.IsValidSeverity(s) {
			t.Errorf("expected %s to be valid severity", s)
		}
	}

	invalidSeverities := []string{"extreme", "unknown", "CRITICAL", ""}
	for _, s := range invalidSeverities {
		if notification.IsValidSeverity(s) {
			t.Errorf("expected %q to be invalid severity", s)
		}
	}
}

func TestIsValidType(t *testing.T) {
	validTypes := []string{
		notification.TypeFindingNew,
		notification.TypeFindingAssigned,
		notification.TypeFindingStatusChange,
		notification.TypeScanCompleted,
		notification.TypeScanFailed,
		notification.TypeAssetDiscovered,
		notification.TypeMemberJoined,
		notification.TypeRoleChanged,
		notification.TypeSLABreach,
		notification.TypeSystemAlert,
	}
	for _, typ := range validTypes {
		if !notification.IsValidType(typ) {
			t.Errorf("expected %s to be valid type", typ)
		}
	}

	invalidTypes := []string{"invalid_type", "FINDING_NEW", "", "scan"}
	for _, typ := range invalidTypes {
		if notification.IsValidType(typ) {
			t.Errorf("expected %q to be invalid type", typ)
		}
	}
}

func TestPreferences_IsTypeMuted(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()
	mutedTypes := []string{notification.TypeMemberJoined, notification.TypeRoleChanged}
	prefs := notification.ReconstitutePref(tenantID, userID, true, "none", mutedTypes, "", time.Now())

	if !prefs.IsTypeMuted(notification.TypeMemberJoined) {
		t.Error("expected member_joined to be muted")
	}
	if !prefs.IsTypeMuted(notification.TypeRoleChanged) {
		t.Error("expected role_changed to be muted")
	}
	if prefs.IsTypeMuted(notification.TypeFindingNew) {
		t.Error("expected finding_new to not be muted")
	}

	// Empty muted types
	emptyPrefs := notification.ReconstitutePref(tenantID, userID, true, "none", nil, "", time.Now())
	if emptyPrefs.IsTypeMuted(notification.TypeFindingNew) {
		t.Error("expected no type to be muted with empty list")
	}
}

func TestPreferences_IsSeverityAllowed(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	tests := []struct {
		name        string
		minSeverity string
		severity    string
		expected    bool
	}{
		{"empty min allows all", "", notification.SeverityInfo, true},
		{"empty min allows critical", "", notification.SeverityCritical, true},
		{"min high allows critical", notification.SeverityHigh, notification.SeverityCritical, true},
		{"min high allows high", notification.SeverityHigh, notification.SeverityHigh, true},
		{"min high blocks medium", notification.SeverityHigh, notification.SeverityMedium, false},
		{"min high blocks low", notification.SeverityHigh, notification.SeverityLow, false},
		{"min high blocks info", notification.SeverityHigh, notification.SeverityInfo, false},
		{"min critical allows only critical", notification.SeverityCritical, notification.SeverityCritical, true},
		{"min critical blocks high", notification.SeverityCritical, notification.SeverityHigh, false},
		{"min info allows all", notification.SeverityInfo, notification.SeverityInfo, true},
		{"min info allows low", notification.SeverityInfo, notification.SeverityLow, true},
		{"min medium allows medium", notification.SeverityMedium, notification.SeverityMedium, true},
		{"min medium allows high", notification.SeverityMedium, notification.SeverityHigh, true},
		{"min medium blocks low", notification.SeverityMedium, notification.SeverityLow, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefs := notification.ReconstitutePref(tenantID, userID, true, "none", nil, tt.minSeverity, time.Now())
			result := prefs.IsSeverityAllowed(tt.severity)
			if result != tt.expected {
				t.Errorf("IsSeverityAllowed(%s) with minSeverity %s: got %v, want %v",
					tt.severity, tt.minSeverity, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// 2. Service Tests — ListNotifications
// =============================================================================

func TestListNotifications_Success(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Seed notifications
	n := notification.NewNotification(notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceAll,
		NotificationType: notification.TypeSystemAlert,
		Title:            "Test",
		Body:             "Body",
		Severity:         notification.SeverityInfo,
	})
	repo.notifications[n.ID()] = n

	page := pagination.New(1, 20)
	result, err := svc.ListNotifications(ctx, tenantID, userID, notification.ListFilter{}, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 item, got %d", len(result.Data))
	}
	if repo.listCalls != 1 {
		t.Errorf("expected 1 list call, got %d", repo.listCalls)
	}
}

func TestListNotifications_Empty(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	result, err := svc.ListNotifications(ctx, tenantID, userID, notification.ListFilter{}, pagination.New(1, 20))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
	if len(result.Data) != 0 {
		t.Errorf("expected 0 items, got %d", len(result.Data))
	}
}

func TestListNotifications_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.listErr = errors.New("db connection failed")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	_, err := svc.ListNotifications(ctx, shared.NewID(), shared.NewID(), notification.ListFilter{}, pagination.New(1, 20))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.listErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

// =============================================================================
// 2. Service Tests — GetUnreadCount
// =============================================================================

func TestGetUnreadCount_Success(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.unreadCountResult = 5
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	count, err := svc.GetUnreadCount(ctx, shared.NewID(), shared.NewID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
	if repo.unreadCountCalls != 1 {
		t.Errorf("expected 1 unread count call, got %d", repo.unreadCountCalls)
	}
}

func TestGetUnreadCount_Zero(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.unreadCountResult = 0
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	count, err := svc.GetUnreadCount(ctx, shared.NewID(), shared.NewID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}

func TestGetUnreadCount_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.unreadCountErr = errors.New("db error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	_, err := svc.GetUnreadCount(ctx, shared.NewID(), shared.NewID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.unreadCountErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

// =============================================================================
// 2. Service Tests — MarkAsRead
// =============================================================================

func TestMarkAsRead_Success(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	notifID := shared.NewID()
	userID := shared.NewID()

	err := svc.MarkAsRead(ctx, tenantID, notifID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.markAsReadCalls != 1 {
		t.Errorf("expected 1 mark as read call, got %d", repo.markAsReadCalls)
	}
	key := fmt.Sprintf("%s:%s:%s", tenantID, notifID, userID)
	if !repo.readStatus[key] {
		t.Error("expected notification to be marked as read in repo")
	}
}

func TestMarkAsRead_NotFound(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.markAsReadErr = notification.ErrNotificationNotFound
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	err := svc.MarkAsRead(ctx, shared.NewID(), shared.NewID(), shared.NewID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, notification.ErrNotificationNotFound) {
		t.Errorf("expected ErrNotificationNotFound, got: %v", err)
	}
}

func TestMarkAsRead_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.markAsReadErr = errors.New("db error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	err := svc.MarkAsRead(ctx, shared.NewID(), shared.NewID(), shared.NewID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.markAsReadErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

// =============================================================================
// 2. Service Tests — MarkAllAsRead
// =============================================================================

func TestMarkAllAsRead_Success(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	err := svc.MarkAllAsRead(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.markAllAsReadCalls != 1 {
		t.Errorf("expected 1 mark all as read call, got %d", repo.markAllAsReadCalls)
	}
}

func TestMarkAllAsRead_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.markAllAsReadErr = errors.New("db error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	err := svc.MarkAllAsRead(ctx, shared.NewID(), shared.NewID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.markAllAsReadErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

// =============================================================================
// 2. Service Tests — GetPreferences
// =============================================================================

func TestGetPreferences_Existing(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	saved := notification.ReconstitutePref(
		tenantID, userID, false, "weekly",
		[]string{notification.TypeScanFailed}, notification.SeverityHigh, time.Now(),
	)
	key := fmt.Sprintf("%s:%s", tenantID, userID)
	repo.preferences[key] = saved

	prefs, err := svc.GetPreferences(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefs.InAppEnabled() {
		t.Error("expected inAppEnabled false")
	}
	if prefs.EmailDigest() != "weekly" {
		t.Errorf("expected emailDigest 'weekly', got %s", prefs.EmailDigest())
	}
	if prefs.MinSeverity() != notification.SeverityHigh {
		t.Errorf("expected minSeverity high, got %s", prefs.MinSeverity())
	}
	if len(prefs.MutedTypes()) != 1 || prefs.MutedTypes()[0] != notification.TypeScanFailed {
		t.Errorf("expected muted types [scan_failed], got %v", prefs.MutedTypes())
	}
}

func TestGetPreferences_Default(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	prefs, err := svc.GetPreferences(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !prefs.InAppEnabled() {
		t.Error("expected default inAppEnabled true")
	}
	if prefs.EmailDigest() != "none" {
		t.Errorf("expected default emailDigest 'none', got %s", prefs.EmailDigest())
	}
	if prefs.MinSeverity() != "" {
		t.Errorf("expected default empty minSeverity, got %s", prefs.MinSeverity())
	}
}

func TestGetPreferences_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.getPreferencesErr = errors.New("db error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	_, err := svc.GetPreferences(ctx, shared.NewID(), shared.NewID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.getPreferencesErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

// =============================================================================
// 2. Service Tests — UpdatePreferences
// =============================================================================

func TestUpdatePreferences_AllFields(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	inApp := false
	digest := "daily"
	minSev := "high"
	input := app.UpdatePreferencesInput{
		InAppEnabled: &inApp,
		EmailDigest:  &digest,
		MutedTypes:   []string{notification.TypeMemberJoined},
		MinSeverity:  &minSev,
	}

	prefs, err := svc.UpdatePreferences(ctx, tenantID, userID, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefs.InAppEnabled() {
		t.Error("expected inAppEnabled false")
	}
	if prefs.EmailDigest() != "daily" {
		t.Errorf("expected emailDigest 'daily', got %s", prefs.EmailDigest())
	}
	if prefs.MinSeverity() != "high" {
		t.Errorf("expected minSeverity 'high', got %s", prefs.MinSeverity())
	}
	if len(prefs.MutedTypes()) != 1 || prefs.MutedTypes()[0] != notification.TypeMemberJoined {
		t.Errorf("expected muted types [member_joined], got %v", prefs.MutedTypes())
	}
	if repo.upsertPrefsCalls != 1 {
		t.Errorf("expected 1 upsert call, got %d", repo.upsertPrefsCalls)
	}
}

func TestUpdatePreferences_PartialUpdate(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Seed existing preferences
	existing := notification.ReconstitutePref(
		tenantID, userID, true, "weekly",
		[]string{notification.TypeScanFailed}, notification.SeverityMedium, time.Now(),
	)
	key := fmt.Sprintf("%s:%s", tenantID, userID)
	repo.preferences[key] = existing

	// Only update email digest
	digest := "daily"
	input := app.UpdatePreferencesInput{
		EmailDigest: &digest,
	}

	prefs, err := svc.UpdatePreferences(ctx, tenantID, userID, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Email digest should be updated
	if prefs.EmailDigest() != "daily" {
		t.Errorf("expected emailDigest 'daily', got %s", prefs.EmailDigest())
	}
	// Other fields should be preserved from existing
	if !prefs.InAppEnabled() {
		t.Error("expected inAppEnabled to be preserved as true")
	}
	if prefs.MinSeverity() != notification.SeverityMedium {
		t.Errorf("expected minSeverity to be preserved as 'medium', got %s", prefs.MinSeverity())
	}
	if len(prefs.MutedTypes()) != 1 || prefs.MutedTypes()[0] != notification.TypeScanFailed {
		t.Errorf("expected muted types to be preserved as [scan_failed], got %v", prefs.MutedTypes())
	}
}

func TestUpdatePreferences_InvalidEmailDigest(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	digest := "hourly"
	input := app.UpdatePreferencesInput{
		EmailDigest: &digest,
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestUpdatePreferences_InvalidMinSeverity(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	sev := "extreme"
	input := app.UpdatePreferencesInput{
		MinSeverity: &sev,
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestUpdatePreferences_InvalidMutedType(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	input := app.UpdatePreferencesInput{
		MutedTypes: []string{notification.TypeFindingNew, "invalid_type"},
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestUpdatePreferences_MutedTypesExceedMax(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	// Create 51 types (exceeds max of 50)
	types := make([]string, 51)
	for i := range types {
		types[i] = notification.TypeFindingNew
	}

	input := app.UpdatePreferencesInput{
		MutedTypes: types,
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestUpdatePreferences_ClearMinSeverity(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Seed existing with minSeverity set
	existing := notification.ReconstitutePref(
		tenantID, userID, true, "none",
		nil, notification.SeverityHigh, time.Now(),
	)
	key := fmt.Sprintf("%s:%s", tenantID, userID)
	repo.preferences[key] = existing

	// Clear min severity with empty string
	empty := ""
	input := app.UpdatePreferencesInput{
		MinSeverity: &empty,
	}

	prefs, err := svc.UpdatePreferences(ctx, tenantID, userID, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prefs.MinSeverity() != "" {
		t.Errorf("expected empty minSeverity, got %s", prefs.MinSeverity())
	}
}

func TestUpdatePreferences_GetExistingError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.getPreferencesErr = errors.New("db error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	digest := "daily"
	input := app.UpdatePreferencesInput{
		EmailDigest: &digest,
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.getPreferencesErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

func TestUpdatePreferences_UpsertError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.upsertPrefsErr = errors.New("db upsert error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	digest := "daily"
	input := app.UpdatePreferencesInput{
		EmailDigest: &digest,
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.upsertPrefsErr) {
		t.Errorf("expected wrapped upsert error, got: %v", err)
	}
}

// =============================================================================
// 2. Service Tests — Notify
// =============================================================================

func TestNotify_Success(t *testing.T) {
	repo := newMockNotificationRepo()
	ws := newMockWSBroadcaster()
	svc := newTestNotificationService(repo, ws)
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceUser,
		AudienceID:       &userID,
		NotificationType: notification.TypeFindingNew,
		Title:            "New Finding",
		Body:             "Critical vuln",
		Severity:         notification.SeverityCritical,
	}

	err := svc.Notify(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
	if len(repo.notifications) != 1 {
		t.Errorf("expected 1 notification stored, got %d", len(repo.notifications))
	}
	// 2 broadcasts: tenant channel (for bell) + audience-specific channel
	if len(ws.calls) != 2 {
		t.Errorf("expected 2 ws broadcasts, got %d", len(ws.calls))
	}
}

func TestNotify_AudienceAll(t *testing.T) {
	repo := newMockNotificationRepo()
	ws := newMockWSBroadcaster()
	svc := newTestNotificationService(repo, ws)
	ctx := context.Background()
	tenantID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceAll,
		NotificationType: notification.TypeSystemAlert,
		Title:            "System Alert",
		Body:             "Maintenance",
		Severity:         notification.SeverityInfo,
	}

	err := svc.Notify(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ws.calls) != 1 {
		t.Fatalf("expected 1 ws broadcast, got %d", len(ws.calls))
	}
	expectedChannel := fmt.Sprintf("tenant:%s", tenantID.String())
	if ws.calls[0].channel != expectedChannel {
		t.Errorf("expected channel %s, got %s", expectedChannel, ws.calls[0].channel)
	}
	if ws.calls[0].tenantID != tenantID.String() {
		t.Errorf("expected tenantID %s, got %s", tenantID.String(), ws.calls[0].tenantID)
	}
}

func TestNotify_AudienceUser(t *testing.T) {
	repo := newMockNotificationRepo()
	ws := newMockWSBroadcaster()
	svc := newTestNotificationService(repo, ws)
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceUser,
		AudienceID:       &userID,
		NotificationType: notification.TypeFindingAssigned,
		Title:            "Finding Assigned",
		Body:             "You have been assigned",
		Severity:         notification.SeverityMedium,
	}

	err := svc.Notify(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 broadcasts: tenant channel (for bell) + user-specific channel
	if len(ws.calls) != 2 {
		t.Fatalf("expected 2 ws broadcasts, got %d", len(ws.calls))
	}
	// First broadcast is always tenant channel
	expectedTenantChannel := fmt.Sprintf("tenant:%s", tenantID.String())
	if ws.calls[0].channel != expectedTenantChannel {
		t.Errorf("expected channel %s, got %s", expectedTenantChannel, ws.calls[0].channel)
	}
	// Second broadcast is audience-specific channel
	expectedUserChannel := fmt.Sprintf("notification:%s", userID.String())
	if ws.calls[1].channel != expectedUserChannel {
		t.Errorf("expected channel %s, got %s", expectedUserChannel, ws.calls[1].channel)
	}
}

func TestNotify_AudienceGroup(t *testing.T) {
	repo := newMockNotificationRepo()
	ws := newMockWSBroadcaster()
	svc := newTestNotificationService(repo, ws)
	ctx := context.Background()
	tenantID := shared.NewID()
	groupID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceGroup,
		AudienceID:       &groupID,
		NotificationType: notification.TypeSLABreach,
		Title:            "SLA Breach",
		Body:             "SLA breached for group",
		Severity:         notification.SeverityHigh,
	}

	err := svc.Notify(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 broadcasts: tenant channel (for bell) + group-specific channel
	if len(ws.calls) != 2 {
		t.Fatalf("expected 2 ws broadcasts, got %d", len(ws.calls))
	}
	expectedTenantChannel := fmt.Sprintf("tenant:%s", tenantID.String())
	if ws.calls[0].channel != expectedTenantChannel {
		t.Errorf("expected channel %s, got %s", expectedTenantChannel, ws.calls[0].channel)
	}
	expectedGroupChannel := fmt.Sprintf("group:%s", groupID.String())
	if ws.calls[1].channel != expectedGroupChannel {
		t.Errorf("expected channel %s, got %s", expectedGroupChannel, ws.calls[1].channel)
	}
}

func TestNotify_NilWSHub(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, nil)
	ctx := context.Background()
	tenantID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceAll,
		NotificationType: notification.TypeSystemAlert,
		Title:            "Alert",
		Body:             "Body",
		Severity:         notification.SeverityInfo,
	}

	// Should not panic
	err := svc.Notify(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
}

func TestNotify_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.createErr = errors.New("db error")
	ws := newMockWSBroadcaster()
	svc := newTestNotificationService(repo, ws)
	ctx := context.Background()

	params := notification.NotificationParams{
		TenantID:         shared.NewID(),
		Audience:         notification.AudienceAll,
		NotificationType: notification.TypeSystemAlert,
		Title:            "Alert",
		Body:             "Body",
		Severity:         notification.SeverityInfo,
	}

	err := svc.Notify(ctx, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.createErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
	// Should NOT push to WebSocket on error
	if len(ws.calls) != 0 {
		t.Errorf("expected 0 ws broadcasts on error, got %d", len(ws.calls))
	}
}

func TestNotify_AllFields(t *testing.T) {
	repo := newMockNotificationRepo()
	ws := newMockWSBroadcaster()
	svc := newTestNotificationService(repo, ws)
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()
	resourceID := shared.NewID()
	actorID := shared.NewID()

	params := notification.NotificationParams{
		TenantID:         tenantID,
		Audience:         notification.AudienceUser,
		AudienceID:       &userID,
		NotificationType: notification.TypeFindingNew,
		Title:            "Critical Finding",
		Body:             "SQL Injection detected",
		Severity:         notification.SeverityCritical,
		ResourceType:     "finding",
		ResourceID:       &resourceID,
		URL:              "/findings/abc",
		ActorID:          &actorID,
	}

	err := svc.Notify(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify notification was stored
	if len(repo.notifications) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(repo.notifications))
	}
	for _, n := range repo.notifications {
		if n.Title() != "Critical Finding" {
			t.Errorf("expected title 'Critical Finding', got %s", n.Title())
		}
		if n.ResourceType() != "finding" {
			t.Errorf("expected resourceType 'finding', got %s", n.ResourceType())
		}
		if n.ResourceID() == nil || !n.ResourceID().Equals(resourceID) {
			t.Errorf("expected resourceID %s, got %v", resourceID, n.ResourceID())
		}
		if n.ActorID() == nil || !n.ActorID().Equals(actorID) {
			t.Errorf("expected actorID %s, got %v", actorID, n.ActorID())
		}
		if n.URL() != "/findings/abc" {
			t.Errorf("expected URL '/findings/abc', got %s", n.URL())
		}
	}
}

// =============================================================================
// 2. Service Tests — CleanupOld
// =============================================================================

func TestCleanupOld_Success(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.deleteOlderResult = 42
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	deleted, err := svc.CleanupOld(ctx, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 42 {
		t.Errorf("expected 42 deleted, got %d", deleted)
	}
	if repo.deleteOlderCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", repo.deleteOlderCalls)
	}
	expectedAge := 30 * 24 * time.Hour
	if repo.lastDeleteAge != expectedAge {
		t.Errorf("expected age %v, got %v", expectedAge, repo.lastDeleteAge)
	}
}

func TestCleanupOld_NothingToDelete(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.deleteOlderResult = 0
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	deleted, err := svc.CleanupOld(ctx, 90)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
}

func TestCleanupOld_InvalidRetentionDays(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	// Zero days
	_, err := svc.CleanupOld(ctx, 0)
	if err == nil {
		t.Fatal("expected validation error for 0 days, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}

	// Negative days
	_, err = svc.CleanupOld(ctx, -5)
	if err == nil {
		t.Fatal("expected validation error for negative days, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}

	// Should not have called repo
	if repo.deleteOlderCalls != 0 {
		t.Errorf("expected 0 delete calls, got %d", repo.deleteOlderCalls)
	}
}

func TestCleanupOld_RepoError(t *testing.T) {
	repo := newMockNotificationRepo()
	repo.deleteOlderErr = errors.New("db error")
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	_, err := svc.CleanupOld(ctx, 30)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repo.deleteOlderErr) {
		t.Errorf("expected wrapped db error, got: %v", err)
	}
}

// =============================================================================
// 3. Validation Tests
// =============================================================================

func TestValidatePreferencesInput_ValidEmailDigests(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	validDigests := []string{"none", "daily", "weekly"}
	for _, d := range validDigests {
		digest := d
		input := app.UpdatePreferencesInput{
			EmailDigest: &digest,
		}
		_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
		if err != nil {
			t.Errorf("expected no error for email digest %q, got: %v", d, err)
		}
	}
}

func TestValidatePreferencesInput_EmptyInput(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	// All nil fields should pass validation
	input := app.UpdatePreferencesInput{}
	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err != nil {
		t.Fatalf("expected no error for empty input, got: %v", err)
	}
}

func TestValidatePreferencesInput_AllValid(t *testing.T) {
	repo := newMockNotificationRepo()
	svc := newTestNotificationService(repo, newMockWSBroadcaster())
	ctx := context.Background()

	inApp := true
	digest := "weekly"
	sev := "medium"
	input := app.UpdatePreferencesInput{
		InAppEnabled: &inApp,
		EmailDigest:  &digest,
		MutedTypes: []string{
			notification.TypeFindingNew,
			notification.TypeScanCompleted,
			notification.TypeAssetDiscovered,
		},
		MinSeverity: &sev,
	}

	_, err := svc.UpdatePreferences(ctx, shared.NewID(), shared.NewID(), input)
	if err != nil {
		t.Fatalf("expected no error for fully valid input, got: %v", err)
	}
}
