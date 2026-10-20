import type { RemediationCampaign } from '../../api/use-remediation-campaigns'

export function campaign(over: Partial<RemediationCampaign> = {}): RemediationCampaign {
  return {
    id: 'c-1',
    name: 'Q4 TLS hardening',
    description: 'Retire TLS 1.0 everywhere',
    status: 'active',
    priority: 'high',
    assigned_to: 'u-1',
    assigned_team: 'g-1',
    due_date: '2099-10-31T00:00:00Z',
    tags: [],
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    version: 3,
    is_overdue: false,
    can_edit: true,
    summary: {
      tasks: 6,
      live_tasks: 3,
      done_tasks: 3,
      overdue_tasks: 1,
      hidden_tasks: 0,
      findings: 20,
      closed_findings: 12,
      verified_findings: 10,
      progress: 60,
    },
    ...over,
  }
}

export const ownerNames = {
  users: [{ id: 'u-1', name: 'Sam' }],
  groups: [{ id: 'g-1', name: 'Ops' }],
  user: (id?: string) => (id === 'u-1' ? 'Sam' : undefined),
  group: (id?: string) => (id === 'g-1' ? 'Ops' : undefined),
}
