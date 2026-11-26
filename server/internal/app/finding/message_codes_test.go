package finding

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type capturedInApp struct {
	got []notificationdom.NotificationParams
}

func (c *capturedInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.got = append(c.got, p)
	return nil
}

type fixedApprovers struct{ list []FindingApprover }

func (f fixedApprovers) FindingApprovers(context.Context, shared.ID) ([]FindingApprover, error) {
	return f.list, nil
}

func msgOf(t *testing.T, c *capturedInApp) *notificationdom.Message {
	t.Helper()
	if len(c.got) != 1 {
		t.Fatalf("want 1 notice, got %d", len(c.got))
	}
	m := c.got[0].Message
	if m == nil {
		t.Fatal("notice has no message")
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("invalid message: %v", err)
	}
	return m
}

func nested(t *testing.T, v any) string {
	t.Helper()
	m, ok := v.(*notificationdom.Message)
	if !ok {
		t.Fatalf("want nested message, got %T", v)
	}
	return m.Code
}

func TestApprovalRequestedMessage(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	by := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	a := &vulnerability.Approval{RequestedStatus: "false_positive", ExpiresAt: &exp, DecideBy: &by}
	m := approvalRequestedMessage(a, "  SQL   injection ", false)
	pre, _ := m.Params["finding_prefix"].(*notificationdom.Message)
	ex, _ := m.Params["expiry"].(*notificationdom.Message)
	dl, _ := m.Params["deadline"].(*notificationdom.Message)
	if m.Code != "finding.approval.requested" || nested(t, m.Params["status"]) != "finding.approval.subject.false_positive" ||
		pre.Code != "finding.approval.part.finding" || pre.Params["finding"] != "SQL injection" ||
		ex.Code != "finding.approval.part.expiry" || ex.Params["expires_at"] != "2027-01-02T03:04:05Z" ||
		dl.Code != "finding.approval.part.deadline" || dl.Params["decide_by"] != "2026-12-01T00:00:00Z" {
		t.Fatalf("unexpected %+v", m)
	}
	m = approvalRequestedMessage(&vulnerability.Approval{RequestedStatus: "accepted"}, "", true)
	if m.Code != "finding.approval.reminder" {
		t.Fatalf("unexpected %+v", m)
	}
	for _, k := range []string{"finding_prefix", "expiry", "deadline"} {
		if m.Params[k] != "" {
			t.Fatalf("%s must be the empty part", k)
		}
	}
	if nested(t, m.Params["status"]) != "finding.approval.subject.accepted_risk" {
		t.Fatal("status subject")
	}
}

func TestVexFindingsPart(t *testing.T) {
	if vexFindingsPart(nil, 3) != "" {
		t.Fatal("no names")
	}
	m, _ := vexFindingsPart([]string{"a", "b"}, 5).(*notificationdom.Message)
	more, _ := m.Params["more"].(*notificationdom.Message)
	if m.Code != "finding.approval.part.vex_findings" || m.Params["findings"] != "a; b" ||
		more.Code != "finding.approval.part.more" || more.Params["count"] != 3 {
		t.Fatalf("unexpected %+v", m)
	}
	if one, _ := vexFindingsPart([]string{"a"}, 1).(*notificationdom.Message); one == nil || one.Params["more"] != "" {
		t.Fatal("no more")
	}
}

func TestNotifyApprovers_SendsMessage(t *testing.T) {
	uid := shared.NewID()
	inApp := &capturedInApp{}
	s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp,
		approverDir: fixedApprovers{list: []FindingApprover{{UserID: uid.String()}}}}
	a := &vulnerability.Approval{TenantID: shared.NewID(), FindingID: shared.NewID(), RequestedStatus: "false_positive"}
	if n := s.notifyApprovers(context.Background(), a, "XSS", true); n != 1 {
		t.Fatalf("reached %d", n)
	}
	m := msgOf(t, inApp)
	if m.Code != "finding.approval.reminder" || nested(t, m.Params["finding_prefix"]) != "finding.approval.part.finding" {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestNotifyBatchApprovers_Message(t *testing.T) {
	uid := shared.NewID()
	inApp := &capturedInApp{}
	s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp}
	b := &vulnerability.ApprovalBatch{ID: shared.NewID(), TenantID: shared.NewID(), RequestedStatus: vulnerability.FindingStatusAccepted, MemberCount: 4}
	s.notifyBatchApprovers(context.Background(), b, approvalpolicy.Result{Tier: "dual", Required: 2, Eligible: []shared.ID{uid}})
	m := msgOf(t, inApp)
	if m.Code != "finding.approval.batch_requested" || m.Params["count"] != 4 || m.Params["required"] != 2 ||
		nested(t, m.Params["status"]) != "finding.approval.subject.accepted_risk" ||
		nested(t, m.Params["tier"]) != "finding.approval.tier.dual" {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestSendDecisionNotice_Messages(t *testing.T) {
	inApp := &capturedInApp{}
	s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp}
	msg := notificationdom.Msg("finding.approval.decided", "subject", approvalSubject("severity change"),
		"outcome", decisionOutcomeMsg(decisionRejected), "finding", "XSS")
	s.sendDecisionNotice(context.Background(), shared.NewID(), shared.NewID(), shared.NewID(), "t", "b", "/u", msg)
	m := msgOf(t, inApp)
	if m.Code != "finding.approval.decided" || nested(t, m.Params["subject"]) != "finding.approval.subject.severity_change" ||
		nested(t, m.Params["outcome"]) != "finding.approval.outcome.rejected" {
		t.Fatalf("unexpected %+v", m)
	}
	if codeSegment("Bad Value") != "other" || codeSegment("two_person") != "two_person" {
		t.Fatal("codeSegment")
	}
}

func TestNotifyMaterialChange_Message(t *testing.T) {
	cases := map[approvalpolicy.Action]string{
		approvalpolicy.ActionEnd:    "finding.material_change.ended",
		approvalpolicy.ActionRevoke: "finding.material_change.revoked",
	}
	for action, code := range cases {
		inApp := &capturedInApp{}
		s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp}
		d := vulnerability.StandingDecision{TenantID: shared.NewID(), FindingID: shared.NewID(), RequesterID: shared.NewID()}
		s.NotifyMaterialChange(context.Background(), d, action, []approvalpolicy.Signal{approvalpolicy.SignalKEVAdded, approvalpolicy.SignalSeverityRaised})
		m := msgOf(t, inApp)
		if m.Code != code || !hasCodes(m.Params["changes"], "finding.signal.kev_added", "finding.signal.severity_raised") {
			t.Fatalf("%v: unexpected %+v", action, m)
		}
	}
}

func TestAnnounceBulkDismiss_Message(t *testing.T) {
	owner := shared.NewID()
	inApp := &capturedInApp{}
	s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp,
		approverDir: fixedApprovers{list: []FindingApprover{{UserID: owner.String(), Owner: true}}}}
	row := &BulkDismissal{ID: shared.NewID(), TenantID: shared.NewID(), CreatedBy: shared.NewID(), RequestedStatus: "false_positive"}
	s.announceBulkDismiss(context.Background(), row, &BulkDismissResult{Counts: BulkDismissCounts{Decided: 7, Grouped: 2, Skipped: 1}})
	m := msgOf(t, inApp)
	if m.Code != "finding.bulk_dismiss.announced" || m.Params["count"] != 7 || m.Params["decided"] != 7 ||
		m.Params["grouped"] != 2 || m.Params["skipped"] != 1 ||
		nested(t, m.Params["status"]) != "finding.approval.subject.false_positive" {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestNotifySeverityApprovers_Message(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatal(err)
	}
	inApp := &capturedInApp{}
	s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp}
	req := &vulnerability.SeverityRequest{PreviousSeverity: vulnerability.SeverityHigh, RequestedSeverity: vulnerability.SeverityLow}
	s.notifySeverityApprovers(context.Background(), f, req, []shared.ID{shared.NewID()})
	m := msgOf(t, inApp)
	if m.Code != "finding.severity_request.requested" || m.Params["previous_severity"] != "high" ||
		m.Params["requested_severity"] != "low" || m.Params["finding"] == "" {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestAssetRiskNotifyApprovers_Message(t *testing.T) {
	a, err := asset.NewAsset("web-1", asset.AssetTypeHost, asset.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	inApp := &capturedInApp{}
	g := &AssetRiskGovernance{v: &VulnerabilityService{approvalInApp: inApp}, logger: logger.NewNop()}
	req := &asset.RiskChangeRequest{TenantID: shared.NewID(), Lowered: []string{"exposure", "criticality"}}
	g.notifyApprovers(context.Background(), a, req, []shared.ID{shared.NewID()})
	m := msgOf(t, inApp)
	if m.Code != "asset.risk_request.requested" || m.Params["asset"] != "web-1" || !hasCodes(m.Params["fields"], "asset.risk_field.exposure", "asset.risk_field.criticality") {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestDigestMessage(t *testing.T) {
	item := digestItem("false_positive", "XSS")
	m := digestMessage(digestCounts{pending: 3, soon: 1, alone: 2}, []*notificationdom.Message{item}, []*notificationdom.Message{item, item})
	lines, _ := m.Params["lines"].([]notificationdom.Message)
	aloneMsg, _ := m.Params["alone"].(*notificationdom.Message)
	if m.Code != "finding.approval.digest" || m.Params["count"] != 3 || m.Params["soon"] != 1 || m.Params["alone_count"] != 2 ||
		len(lines) != 1 || lines[0].Code != "finding.approval.digest_item" || aloneMsg == nil ||
		aloneMsg.Code != "finding.approval.digest_alone_part" || len(aloneMsg.Params["lines"].([]notificationdom.Message)) != 2 {
		t.Fatalf("unexpected %+v", m)
	}
	m = digestMessage(digestCounts{alone: 2}, nil, []*notificationdom.Message{item})
	if m.Code != "finding.approval.digest_alone" || m.Params["count"] != 2 {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestDeliverDigest_Message(t *testing.T) {
	inApp := &capturedInApp{}
	s := &VulnerabilityService{logger: logger.NewNop(), approvalInApp: inApp}
	msg := digestMessage(digestCounts{pending: 1}, nil, nil)
	s.deliverDigest(context.Background(), shared.NewID(), shared.NewID(), "", digestCounts{pending: 1}, nil, nil, msg)
	if m := msgOf(t, inApp); m.Code != "finding.approval.digest" {
		t.Fatalf("unexpected %+v", m)
	}
}

func TestStatusDigestMessage(t *testing.T) {
	mk := func() *vulnerability.Finding {
		f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	d := &statusDigest{findings: []*vulnerability.Finding{mk(), mk()},
		statuses: map[vulnerability.FindingStatus]struct{}{vulnerability.FindingStatusResolved: {}}}
	m := statusDigestMessage(d)
	if m.Code != "finding.status_digest_moved" || m.Params["count"] != 2 || m.Params["finding_status"] != "resolved" {
		t.Fatalf("unexpected %+v", m)
	}
	d.statuses[vulnerability.FindingStatusConfirmed] = struct{}{}
	if m := statusDigestMessage(d); m.Code != "finding.status_digest_changed" || m.Params["count"] != 2 {
		t.Fatalf("unexpected %+v", m)
	}
}

func hasCodes(v any, want ...string) bool {
	l, ok := v.([]*notificationdom.Message)
	if !ok || len(l) != len(want) {
		return false
	}
	for i, m := range l {
		if m.Code != want[i] {
			return false
		}
	}
	return true
}
