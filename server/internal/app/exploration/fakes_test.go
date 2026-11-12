package exploration

import (
	"context"
	"sync"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// memRepo is an in-memory exploration.Repository with the database's dedup
// and compare-and-set rules.
type memRepo struct {
	mu       sync.Mutex
	ex       map[shared.ID]shared.ID
	leads    map[shared.ID]*exploration.Lead
	links    []exploration.Link
	verdicts []exploration.Verdict
	// inScope are the subject assets a restricted scope sees.
	inScope map[shared.ID]bool
}

func newMemRepo() *memRepo {
	return &memRepo{ex: map[shared.ID]shared.ID{}, leads: map[shared.ID]*exploration.Lead{}, inScope: map[shared.ID]bool{}}
}

func (m *memRepo) EnsureContinuous(_ context.Context, tenantID shared.ID) (shared.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.ex[tenantID]; ok {
		return id, nil
	}
	id := shared.NewID()
	m.ex[tenantID] = id
	return id, nil
}

func (m *memRepo) OpenLead(_ context.Context, l *exploration.Lead, parents []exploration.Link) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.leads {
		if o.TenantID == l.TenantID && o.ExplorationID == l.ExplorationID && o.DedupKey == l.DedupKey && o.State.Live() {
			return false, nil
		}
	}
	c := *l
	m.leads[l.ID] = &c
	for _, p := range parents {
		p.TenantID, p.LeadID, p.Rel = l.TenantID, l.ID, exploration.RelDerivedFrom
		m.links = append(m.links, p)
	}
	return true, nil
}

func (m *memRepo) GetLead(_ context.Context, tenantID, id shared.ID, scope *shared.DataScope) (*exploration.Lead, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.leads[id]
	if !ok || l.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	if scope.Restricted() && (l.SubjectAssetID == nil || !m.inScope[*l.SubjectAssetID]) {
		return nil, shared.ErrNotFound
	}
	c := *l
	return &c, nil
}

func (m *memRepo) ListLeads(_ context.Context, tenantID shared.ID, f exploration.LeadFilter) ([]*exploration.Lead, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*exploration.Lead
	for _, l := range m.leads {
		if l.TenantID != tenantID {
			continue
		}
		if len(f.States) > 0 {
			ok := false
			for _, s := range f.States {
				ok = ok || s == l.State
			}
			if !ok {
				continue
			}
		}
		c := *l
		out = append(out, &c)
	}
	return out, nil
}

func (m *memRepo) SaveLead(_ context.Context, l *exploration.Lead) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.leads[l.ID]
	if !ok || cur.TenantID != l.TenantID || cur.RowVersion != l.RowVersion {
		return exploration.ErrStale
	}
	l.RowVersion++
	c := *l
	m.leads[l.ID] = &c
	return nil
}

func (m *memRepo) AddLinks(_ context.Context, links []exploration.Link) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, k := range links {
		if err := k.Validate(); err != nil {
			return n, err
		}
		dup := false
		for _, o := range m.links {
			dup = dup || (o.LeadID == k.LeadID && o.Rel == k.Rel && o.EndKind == k.EndKind && *o.EndID == *k.EndID)
		}
		if !dup {
			m.links = append(m.links, k)
			n++
		}
	}
	return n, nil
}

func (m *memRepo) AddVerdict(_ context.Context, v exploration.Verdict) error {
	if err := v.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verdicts = append(m.verdicts, v)
	return nil
}

func (m *memRepo) Links(_ context.Context, tenantID, leadID shared.ID) ([]exploration.Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []exploration.Link
	for _, k := range m.links {
		if k.TenantID == tenantID && k.LeadID == leadID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *memRepo) CountLive(_ context.Context, tenantID, explorationID shared.ID, subject *shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, l := range m.leads {
		if l.TenantID == tenantID && l.ExplorationID == explorationID && l.State.Live() &&
			(subject == nil || (l.SubjectAssetID != nil && *l.SubjectAssetID == *subject)) {
			n++
		}
	}
	return n, nil
}

func (m *memRepo) Verdicts(_ context.Context, tenantID, leadID shared.ID) ([]exploration.Verdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []exploration.Verdict
	for _, v := range m.verdicts {
		if v.TenantID == tenantID && v.LeadID == leadID {
			out = append(out, v)
		}
	}
	return out, nil
}

// leadsOf returns the stored leads of a tenant.
func (m *memRepo) leadsOf(tenantID shared.ID) []*exploration.Lead {
	out, _ := m.ListLeads(context.Background(), tenantID, exploration.LeadFilter{})
	return out
}

// fakeTriggers serves fixed candidates per tenant and rule.
type fakeTriggers struct {
	dangling, versions, gone map[shared.ID][]exploration.Candidate
}

func (f *fakeTriggers) DanglingAliases(_ context.Context, t shared.ID, _ string, limit int) ([]exploration.Candidate, error) {
	return capC(f.dangling[t], limit), nil
}

func (f *fakeTriggers) UnconfirmedCriticalMatches(_ context.Context, t shared.ID, _ string, limit int) ([]exploration.Candidate, error) {
	return capC(f.versions[t], limit), nil
}

func (f *fakeTriggers) GoneWithOpenFindings(_ context.Context, t shared.ID, _ string, limit int) ([]exploration.Candidate, error) {
	return capC(f.gone[t], limit), nil
}

func capC(cs []exploration.Candidate, n int) []exploration.Candidate {
	if len(cs) > n {
		return cs[:n]
	}
	return cs
}

type fixedSwitch struct {
	on  bool
	err error
}

func (s fixedSwitch) CoverageEnabled(context.Context, shared.ID) (bool, error) { return s.on, s.err }

type memAudit struct {
	mu     sync.Mutex
	events []auditapp.AuditEvent
	ctxs   []auditapp.AuditContext
}

func (a *memAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	a.ctxs = append(a.ctxs, actx)
	return nil
}
