import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({
  data: undefined as unknown,
  error: undefined as Error | undefined,
  mutate: vi.fn(),
  filters: undefined as unknown,
}))

vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingsApi: (filters: unknown) => {
    state.filters = filters
    return { data: state.data, error: state.error, isLoading: false, mutate: state.mutate }
  },
}))

import { AssetFindings } from '../asset-findings'

function finding(id: string, status: string, severity = 'high') {
  return {
    id,
    title: `Finding ${id}`,
    status,
    severity,
    finding_type: 'vulnerability',
    asset_id: 'a1',
  }
}

beforeEach(() => {
  state.data = undefined
  state.error = undefined
  state.mutate.mockReset()
})

describe('AssetFindings', () => {
  it('asks for open findings only', () => {
    state.data = { data: [finding('1', 'new')], total: 1 }
    render(<AssetFindings assetId="a1" findingCount={1} />)
    expect(state.filters).toMatchObject({ asset_id: 'a1', state: 'open' })
  })

  it('footer count and severity chips come from the asset, not the loaded page', () => {
    state.data = { data: [finding('1', 'new', 'low')], total: 1 }
    render(
      <AssetFindings assetId="a1" findingCount={120} severityCounts={{ critical: 7, high: 113 }} />
    )
    const viewOpen = screen.getByRole('link', { name: /View 120 open findings/ })
    // The same open set as the count, so the list shows that number.
    expect(viewOpen.getAttribute('href')).toMatch(
      /status=new%2Cconfirmed%2Cin_progress%2Cfix_applied/
    )
    expect(screen.getByText(/7 Critical/)).toBeInTheDocument()
    expect(screen.getByText(/113 High/)).toBeInTheDocument()
  })

  it('shows the real status: a duplicate is not Resolved', () => {
    state.data = { data: [finding('1', 'duplicate')], total: 1 }
    render(<AssetFindings assetId="a1" findingCount={1} />)
    expect(screen.getByText('Duplicate')).toBeInTheDocument()
    expect(screen.queryByText('Resolved')).not.toBeInTheDocument()
  })

  it('a failed load shows an error with retry', () => {
    state.error = new Error('boom')
    render(<AssetFindings assetId="a1" />)
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(state.mutate).toHaveBeenCalled()
  })
})
