package scangov

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/server/pkg/domain/scangov"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgSink struct {
	got []notificationdom.NotificationParams
}

func (m *msgSink) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	m.got = append(m.got, p)
	return nil
}

func TestNotifyUserMsg_CarriesMessage(t *testing.T) {
	sink := &msgSink{}
	s := &Service{inApp: sink, log: logger.NewNop()}
	uid := shared.NewID().String()

	s.notifyUserMsg(context.Background(), shared.NewID(), uid, "t", "b", "info", shared.NewID(),
		notificationdom.Msg("scan_approval.approved", "scan", "Nightly"))
	s.notifyUser(context.Background(), shared.NewID(), uid, "t", "b", "info", shared.NewID())
	require.Len(t, sink.got, 2)
	require.NotNil(t, sink.got[0].Message)
	assert.Equal(t, "scan_approval.approved", sink.got[0].Message.Code)
	assert.Equal(t, "Nightly", sink.got[0].Message.Params["scan"])
	assert.Nil(t, sink.got[1].Message)
}

func byCode(got []notificationdom.NotificationParams, code string) []notificationdom.NotificationParams {
	var out []notificationdom.NotificationParams
	for _, p := range got {
		if p.Message != nil && p.Message.Code == code {
			out = append(out, p)
		}
	}
	return out
}

func TestScanApprovalMessages(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, team)
	sink := &msgSink{}
	r.svc.inApp = sink

	req, err := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(member))
	require.NoError(t, err)
	aw := byCode(sink.got, "scan_approval.awaiting_your_approval")
	require.Len(t, aw, 3)
	p := aw[0].Message.Params
	assert.Equal(t, "prod sweep", p["scan"])
	assert.Equal(t, 1, p["targets"])
	assert.Equal(t, 1, p["remaining"])
	assert.NotEmpty(t, p["rules"])
	in, ok := p["intensity"].(*notificationdom.Message)
	require.True(t, ok)
	assert.Contains(t, in.Code, "scan_approval.intensity.")

	_, _, err = r.svc.Remind(ctx, r.tid, req.ID, act(member))
	require.NoError(t, err)
	assert.Len(t, byCode(sink.got, "scan_approval.approval_reminder"), 3)

	_, err = r.svc.Approve(ctx, r.tid, req.ID, "ok", act(admin))
	require.NoError(t, err)
	ap := byCode(sink.got, "scan_approval.approved")
	require.Len(t, ap, 1)
	assert.Contains(t, ap[0].Message.Params, "scan") // the name is filled by the store read, not the in-memory fake

	// Rejected.
	r2 := newRig(t, scangov.ModeOn, team)
	sink2 := &msgSink{}
	r2.svc.inApp = sink2
	req2, _ := r2.svc.Submit(ctx, r2.tid, r2.sc.ID, SubmitInput{Justification: "x"}, act(member))
	_, err = r2.svc.Reject(ctx, r2.tid, req2.ID, "too wide", act(admin))
	require.NoError(t, err)
	rj := byCode(sink2.got, "scan_approval.rejected")
	require.Len(t, rj, 1)
	assert.Equal(t, "too wide", rj[0].Message.Params["note"])
	assert.Contains(t, rj[0].Message.Params, "scan")

	// Emergency.
	r4 := newRig(t, scangov.ModeOn, team)
	sink4 := &msgSink{}
	r4.svc.inApp = sink4
	_, err = r4.svc.Emergency(ctx, r4.tid, r4.sc.ID, EmergencyInput{Reason: "incident", Hours: 2}, act(admin))
	require.NoError(t, err)
	em := byCode(sink4.got, "scan_approval.emergency_run")
	require.Len(t, em, 2)
	assert.Equal(t, "incident", em[0].Message.Params["reason"])
	assert.Equal(t, "prod sweep", em[0].Message.Params["scan"])
	assert.NotEmpty(t, em[0].Message.Params["until_at"])
}

func TestScanApprovalSelfApprovedMessage(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOn, dir{{UserID: owner, Role: "owner"}})
	sink := &msgSink{}
	r.svc.inApp = sink
	req, _ := r.svc.Submit(ctx, r.tid, r.sc.ID, SubmitInput{Justification: "x"}, act(owner))
	_, err := r.svc.SelfApprove(ctx, r.tid, req.ID, "only owner", "123456", act(owner))
	require.NoError(t, err)
	// The acting owner is excluded from the admin notice; the requester still
	// gets the coded approval.
	require.NotEmpty(t, byCode(sink.got, "scan_approval.approved"))
	assert.Empty(t, byCode(sink.got, "scan_approval.self_approved"))

	// With a second admin present the admin notice goes out, coded.
	all := dir{{UserID: owner, Role: "owner"}, {UserID: admin, Role: "admin"}}
	r.svc.notifyAdmins(ctx, r.tid, all, owner, "t", "b", r.sc.ID,
		notificationdom.Msg("scan_approval.self_approved", "scan", "prod sweep", "reason", "only owner"))
	sa := byCode(sink.got, "scan_approval.self_approved")
	require.Len(t, sa, 1)
	assert.Equal(t, "only owner", sa[0].Message.Params["reason"])
}
