package threatalert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type capInApp struct {
	got []notificationdom.NotificationParams
}

func (c *capInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.got = append(c.got, p)
	return nil
}

type oneAdmin struct{ id shared.ID }

func (o oneAdmin) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{o.id}, nil
}

func newCapPlanner() (*Planner, *capInApp) {
	c := &capInApp{}
	p := &Planner{logger: logger.NewNop(), inApp: c, admins: oneAdmin{shared.NewID()}}
	return p, c
}

func nested(t *testing.T, m *notificationdom.Message, key string) *notificationdom.Message {
	t.Helper()
	n, ok := m.Params[key].(*notificationdom.Message)
	require.True(t, ok, key)
	return n
}

func TestSendImmediate_Message(t *testing.T) {
	p, c := newCapPlanner()
	epss := 0.97
	a := &threatalert.Alert{TenantID: shared.NewID(), ID: shared.NewID(), VulnID: "CVE-2099-1", Title: "Big bug",
		InKEV: true, KEVRansomware: true, EPSS: &epss, Severity: "critical", Confirmed: 3, Likely: 1, InternetFacing: 2}
	a.Breakdown.ExploitationBasis = threatalert.BasisInTheWild
	p.sendImmediate(context.Background(), &policy{}, a)
	require.Len(t, c.got, 1)
	m := c.got[0].Message
	require.NotNil(t, m)
	assert.Equal(t, "threat.urgent", m.Code)
	assert.Equal(t, "Big bug", m.Params["title"])
	why := nested(t, m, "why")
	assert.Equal(t, "threat.why", why.Code)
	parts, _ := why.Params["parts"].([]notificationdom.Message)
	require.Len(t, parts, 4)
	assert.Equal(t, "threat.why.kev_ransomware", parts[0].Code)
	assert.Equal(t, "threat.exploitation."+threatalert.BasisInTheWild, parts[1].Code)
	assert.Equal(t, "threat.why.epss", parts[2].Code)
	assert.Equal(t, "0.97", parts[2].Params["epss"])
	assert.Equal(t, "threat.why.severity", parts[3].Code)
	assert.Equal(t, "critical", parts[3].Params["severity"])
	none, _ := whyMessage(&threatalert.Alert{}).Params["parts"].([]notificationdom.Message)
	require.Len(t, none, 1)
	assert.Equal(t, "threat.why.new", none[0].Code)
	assert.Equal(t, "threat.hosts_none", hostsMessage(threatalert.HostCounts{}).Code)
	hosts := nested(t, m, "hosts")
	assert.Equal(t, "threat.hosts", hosts.Code)
	assert.Equal(t, 4, hosts.Params["total"])
	assert.Equal(t, 3, hosts.Params["confirmed"])
	assert.Equal(t, 1, hosts.Params["likely"])
	assert.Equal(t, 0, hosts.Params["possible"])
	assert.Equal(t, 2, hosts.Params["internet_facing"])
}

func TestSendSummary_Message(t *testing.T) {
	p, c := newCapPlanner()
	alerts := make([]*threatalert.Alert, 0, 12)
	for i := 0; i < 12; i++ {
		alerts = append(alerts, &threatalert.Alert{VulnID: "CVE-2099-7", ETS: 50, Confirmed: 1})
	}
	p.sendSummary(context.Background(), &policy{}, shared.NewID(), alerts, true)
	require.Len(t, c.got, 1)
	m := c.got[0].Message
	assert.Equal(t, "threat.summary_quiet", m.Code)
	assert.Equal(t, 12, m.Params["count"])
	assert.Equal(t, 2, m.Params["more"])
	lines, _ := m.Params["lines"].([]notificationdom.Message)
	require.Len(t, lines, 10)
	assert.Equal(t, "threat.item", lines[0].Code)
	assert.Equal(t, "CVE-2099-7", lines[0].Params["vuln"])
	assert.Equal(t, 50, lines[0].Params["score"])

	c.got = nil
	p.sendSummary(context.Background(), &policy{}, shared.NewID(), alerts[:2], false)
	assert.Equal(t, "threat.summary_overflow", c.got[0].Message.Code)
	assert.Equal(t, 0, c.got[0].Message.Params["more"])
}

func TestDigestMessage(t *testing.T) {
	m := digestMessage(threatalert.Digest{Exploited: 4}, true)
	assert.Equal(t, "threat.digest_baseline", m.Code)
	assert.Equal(t, 4, m.Params["count"])

	m = digestMessage(threatalert.Digest{Immediate: 1, Digest: 2, Listed: 3, Resolved: 4, KEV: 5,
		Top: []threatalert.DigestItem{{VulnID: "CVE-2099-1", ETS: 91, Confirmed: 3}}}, false)
	assert.Equal(t, "threat.digest", m.Code)
	assert.Equal(t, 1, m.Params["urgent"])
	assert.Equal(t, 2, m.Params["review"])
	assert.Equal(t, 3, m.Params["listed"])
	assert.Equal(t, 4, m.Params["resolved"])
	assert.Equal(t, 5, m.Params["kev"])
	lines, _ := m.Params["lines"].([]notificationdom.Message)
	require.Len(t, lines, 1)
	assert.Equal(t, 91, lines[0].Params["score"])
}
