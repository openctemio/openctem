/**
 * The asset's Next steps card: loading, empty, up to three steps saying what
 * is checked, why and where it stands, "See all" to the Exploration page for
 * the asset, the Ask button only with scans:execute, and no section when the
 * list cannot be read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ReactNode } from 'react'
import { render, screen, within } from '@testing-library/react'
import type { Lead } from '../../lib/leads'

const state: { leads: Lead[]; error: unknown; isLoading: boolean; canExecute: boolean } = {
  leads: [],
  error: undefined,
  isLoading: false,
  canExecute: true,
}
const useAssetLeads = vi.fn()

vi.mock('../../hooks/use-leads', () => ({
  useAssetLeads: (id: string, limit: number) => {
    useAssetLeads(id, limit)
    return { leads: state.leads, error: state.error, isLoading: state.isLoading, mutate: vi.fn() }
  },
  useRevalidateLeads: () => vi.fn(),
  askLead: vi.fn(),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: ReactNode }) => (state.canExecute ? children : null),
}))

const { AssetNextSteps } = await import('../asset-next-steps')

const ASSET = '11111111-1111-4111-8111-111111111111'

function lead(over: Partial<Lead>): Lead {
  return {
    id: 'l1',
    type: 'dns.takeover_check',
    state: 'open',
    capability: 'check.takeover',
    tier: 1,
    subject_asset_id: ASSET,
    reason_code: 'cname_dangling',
    rationale: '',
    origin: 'rule',
    likelihood: 'medium',
    score: 1,
    attempts: 0,
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-02T00:00:00Z',
    ...over,
  }
}

describe('AssetNextSteps', () => {
  beforeEach(() => {
    state.leads = []
    state.error = undefined
    state.isLoading = false
    state.canExecute = true
    useAssetLeads.mockClear()
  })

  it('asks for at most three steps of this asset', () => {
    render(<AssetNextSteps assetId={ASSET} />)
    expect(useAssetLeads).toHaveBeenCalledWith(ASSET, 3)
  })

  it('says when nothing is planned, without See all', () => {
    render(<AssetNextSteps assetId={ASSET} />)
    expect(screen.getByRole('region', { name: 'Next steps' })).toBeInTheDocument()
    expect(screen.getByTestId('next-steps-empty')).toHaveTextContent(
      'No next step is planned for this asset.'
    )
    expect(screen.queryByRole('link', { name: 'See all' })).toBeNull()
  })

  it('shows each step with what, why and its state', () => {
    state.leads = [
      lead({ id: 'a', state: 'awaiting_approval' }),
      lead({
        id: 'b',
        state: 'open',
        type: 'version.confirm',
        reason_code: 'kev_on_unconfirmed_version',
      }),
      lead({ id: 'c', state: 'running' }),
      lead({ id: 'd', state: 'refuted', closed_at: '2026-11-03T12:00:00Z' }),
    ]
    render(<AssetNextSteps assetId={ASSET} />)
    const items = within(screen.getByTestId('next-steps')).getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(items[0]).toHaveTextContent('Can this dangling alias be claimed by someone else?')
    expect(items[0]).toHaveTextContent(
      'Because: Its alias points to a target that no longer answers'
    )
    expect(within(items[0]).getByTestId('next-step-status')).toHaveTextContent(
      'Waiting for approval'
    )
    expect(within(items[1]).getByTestId('next-step-status')).toHaveTextContent('Scheduled')
    expect(within(items[2]).getByTestId('next-step-status')).toHaveTextContent('Running')
    expect(screen.getByRole('link', { name: 'See all' })).toHaveAttribute(
      'href',
      `/exploration?asset=${ASSET}`
    )
  })

  it('says a finished step found nothing, with its date', () => {
    state.leads = [lead({ id: 'd', state: 'refuted', closed_at: '2026-11-03T12:00:00Z' })]
    render(<AssetNextSteps assetId={ASSET} />)
    expect(screen.getByTestId('next-step-status')).toHaveTextContent(/^Done: nothing found, /)
  })

  it('offers Ask only with permission to run scans', () => {
    render(<AssetNextSteps assetId={ASSET} />)
    expect(screen.getByRole('button', { name: 'Ask' })).toBeInTheDocument()
    state.canExecute = false
    render(<AssetNextSteps assetId={ASSET} />)
    expect(screen.getAllByRole('button', { name: 'Ask' })).toHaveLength(1)
  })

  it('hides when the list cannot be read', () => {
    state.error = new Error('boom')
    const { container } = render(<AssetNextSteps assetId={ASSET} />)
    expect(container).toBeEmptyDOMElement()
  })
})
