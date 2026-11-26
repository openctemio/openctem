package scope

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type noticeSink struct {
	got []notificationdom.NotificationParams
}

func (n *noticeSink) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.got = append(n.got, p)
	return nil
}

type noticeAdmins struct{}

func (noticeAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{shared.NewID()}, nil
}

func nestedMsg(t *testing.T, m *notificationdom.Message, key string) *notificationdom.Message {
	t.Helper()
	n, ok := m.Params[key].(*notificationdom.Message)
	require.True(t, ok, key)
	return n
}

func TestNotifyWidened_MessageCode(t *testing.T) {
	sink := &noticeSink{}
	s := &Service{logger: logger.NewNop(), admins: noticeAdmins{}, inApp: sink}
	tgt, err := scopedom.NewTarget(shared.NewID(), scopedom.TargetTypeDomain, "example.com", "", "u")
	require.NoError(t, err)

	cases := map[string]string{
		"Scope entry added":                     "scope.entry_added",
		"Scope entry widened":                   "scope.entry_widened",
		"Discovery turned on for a scope entry": "scope.discovery_on",
		"Scope entry activated":                 "scope.entry_activated",
		"Scope entry approved and in effect":    "scope.entry_approved",
	}
	for title, code := range cases {
		sink.got = nil
		s.notifyWidened(context.Background(), tgt, title, code)
		require.Len(t, sink.got, 1, title)
		m := sink.got[0].Message
		require.NotNil(t, m, title)
		assert.Equal(t, code, m.Code)
		assert.Equal(t, "example.com", m.Params["pattern"])
		assert.Equal(t, "scope.target_type.domain", nestedMsg(t, m, "target_type").Code)
		assert.Contains(t, nestedMsg(t, m, "max_tier").Code, "scope.tier.")
		assert.Equal(t, "scope.expiry.permanent", nestedMsg(t, m, "expiry").Code)
	}
}

func TestRequestMessage_Values(t *testing.T) {
	tgt, err := scopedom.NewTarget(shared.NewID(), scopedom.TargetTypeDomain, "example.com", "", "u")
	require.NoError(t, err)
	m := requestMessage("scope.awaiting_approval", tgt)
	assert.Equal(t, "scope.awaiting_approval", m.Code)
	assert.Equal(t, tgt.RemainingApprovals(), m.Params["remaining"])
	assert.Equal(t, tgt.Reason(), m.Params["reason"])
	assert.Equal(t, "example.com", m.Params["pattern"])
	assert.NoError(t, m.Validate())
}

func TestScopeCodeSegment(t *testing.T) {
	assert.Equal(t, "other", scopeCodeSegment("Ip Range"))
	assert.Equal(t, "ip_range", scopeCodeSegment("ip_range"))
}

func TestNoticeMessages_Remaining(t *testing.T) {
	tgt, err := scopedom.NewTarget(shared.NewID(), scopedom.TargetTypeDomain, "example.com", "why", "u")
	require.NoError(t, err)

	b := bulkMessage([]*scopedom.Target{tgt})
	assert.Equal(t, "scope.bulk_added_one", b.Code)
	assert.Equal(t, 1, b.Params["count"])
	assert.Equal(t, 0, b.Params["more"])
	es := b.Params["entries"].([]notificationdom.Message)
	require.Len(t, es, 1)
	assert.Equal(t, "example.com", es[0].Params["pattern"])
	many := make([]*scopedom.Target, 12)
	for i := range many {
		many[i] = tgt
	}
	b = bulkMessage(many)
	assert.Equal(t, "scope.bulk_added", b.Code)
	assert.Equal(t, 12, b.Params["count"])
	assert.Equal(t, 2, b.Params["more"])
	assert.Len(t, b.Params["entries"], 10)
	assert.NoError(t, b.Validate())

	r := replacedMessage(scopedom.TargetTypeDomain, "new.com", "old.com",
		scopedom.CoverageChange{Added: []string{"new.com"}}, "rename")
	assert.Equal(t, "scope.pattern_replaced", r.Code)
	assert.Equal(t, "new.com", r.Params["added"])
	assert.Equal(t, "scope.change.nothing", nestedMsg(t, r, "removed").Code)
	assert.Equal(t, "old.com", r.Params["old_pattern"])
	assert.Equal(t, "rename", r.Params["reason"])

	until := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	w := testingChangeMessage("a.example.com", &scopedom.WebRule{PathPrefix: "/admin", Testing: scopedom.TestingReadOnly})
	assert.Equal(t, "scope.exclusion_testing_changed", w.Code)
	assert.Equal(t, "scope.testing.read_only", nestedMsg(t, w, "testing").Code)
	assert.Equal(t, "/admin", w.Params["path_prefix"])
	assert.Equal(t, "a.example.com", w.Params["host"])
	w = testingChangeMessage("a.example.com", &scopedom.WebRule{PathPrefix: "/admin", Testing: scopedom.TestingAllowed, TestingUntil: &until})
	assert.Equal(t, "scope.exclusion_testing_changed_until", w.Code)
	assert.Equal(t, "2026-01-02T03:04:05Z", w.Params["until_at"])
}

func TestNoticeMessages_Sent(t *testing.T) {
	sink := &noticeSink{}
	s := &Service{logger: logger.NewNop(), admins: noticeAdmins{}, inApp: sink}
	tgt, err := scopedom.NewTarget(shared.NewID(), scopedom.TargetTypeDomain, "example.com", "why", "u")
	require.NoError(t, err)
	ctx := context.Background()

	s.requestAttestation(ctx, tgt, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.Len(t, sink.got, 1)
	m := sink.got[0].Message
	require.NotNil(t, m)
	assert.Equal(t, "scope.attestation_requested", m.Code)
	assert.Equal(t, "example.com", m.Params["pattern"])
	assert.Equal(t, tgt.Reason(), m.Params["reason"])
	assert.NotEmpty(t, m.Params["deadline_at"])
	assert.Equal(t, "scope.target_type.domain", nestedMsg(t, m, "target_type").Code)

	sink.got = nil
	s.afterDowngrade(ctx, tgt)
	require.Len(t, sink.got, 1)
	m = sink.got[0].Message
	require.NotNil(t, m)
	assert.Equal(t, "scope.t2_downgraded", m.Code)
	assert.Equal(t, int(scopedom.AttestationGrace.Hours()/24), m.Params["days"])
}
