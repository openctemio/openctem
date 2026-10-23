import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { FindingDetail } from '../../../types'

let perms: string[] = []
const get = vi.fn()

vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a), post: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'member' } }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: (p: string) => perms.includes(p) }),
}))
// The identity section has its own test; here it reads nothing.
vi.mock('../../../api/use-finding-issue-group', () => ({
  useFindingIssueGroup: () => ({ members: [], mutate: vi.fn() }),
  unlinkIssue: vi.fn(),
}))
vi.mock('../../../api/use-finding-identity', () => ({
  useFindingIdentity: () => ({
    identity: null,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
}))
vi.mock('../../../api/use-finding-groups', () => ({ useRelatedCVEs: () => ({ data: undefined }) }))
// The "last seen in" line fetches receipts on its own (receipt-summary.test.tsx).
vi.mock('../../receipt-summary', () => ({ FindingLastSeenIn: () => null }))

const { OverviewTab } = await import('../overview-tab')

function finding(): FindingDetail {
  return {
    id: 'f1',
    title: 'x',
    description: 'd',
    severity: 'high',
    status: 'new',
    source: 'sast',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-05-07T00:00:00Z',
    createdAt: '2026-05-07T00:00:00Z',
    updatedAt: '2026-05-07T00:00:00Z',
    // 25 newer activities than any AI triage: the old source (page 1 of the
    // feed) would not contain the analysis.
    activities: Array.from({ length: 25 }, (_, i) => ({
      id: `a${i}`,
      type: 'comment',
      createdAt: '2026-10-01T00:00:00Z',
    })),
  } as unknown as FindingDetail
}

const triage = {
  id: 'tr1',
  finding_id: 'f1',
  status: 'completed',
  risk_score: 81,
  severity_assessment: 'high',
  false_positive_likelihood: 0.2,
  summary: 'Reachable from the internet; patch this week.',
  created_at: '2026-09-01T00:00:00Z',
  completed_at: '2026-09-01T00:01:00Z',
}

const renderTab = () =>
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <OverviewTab finding={finding()} />
    </SWRConfig>
  )

describe('Overview AI analysis', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    get.mockResolvedValue(triage)
  })

  it('comes from the AI triage endpoint and survives 25 newer activities', async () => {
    perms = ['ai_triage:read']
    renderTab()
    expect(await screen.findByText('Reachable from the internet; patch this week.')).toBeVisible()
    expect(screen.getByText('81 / 100')).toBeInTheDocument()
    expect(screen.getByText('20%')).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('/api/v1/findings/f1/ai-triage')
  })

  it('is not requested, and not shown, without ai_triage:read', async () => {
    perms = []
    renderTab()
    await new Promise((r) => setTimeout(r, 50))
    expect(get).not.toHaveBeenCalled()
    expect(screen.queryByText('AI analysis')).toBeNull()
  })

  it('is not shown while the analysis has not completed', async () => {
    perms = ['ai_triage:read']
    get.mockResolvedValue({ ...triage, status: 'processing' })
    renderTab()
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(screen.queryByText('AI analysis')).toBeNull()
  })
})
