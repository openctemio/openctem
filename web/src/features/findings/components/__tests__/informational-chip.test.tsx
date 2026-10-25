import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { InformationalChip } from '../informational-chip'

const countState: { total: number | undefined; lastFilters?: unknown; enabled?: boolean } = {
  total: 7,
}
vi.mock('../../api/use-findings-count', () => ({
  useFindingsCount: (filters: unknown, enabled: boolean) => {
    countState.lastFilters = filters
    countState.enabled = enabled
    return enabled ? countState.total : undefined
  },
}))
const updatePreferences = vi.fn(async () => ({}))
vi.mock('@/features/account/api/use-preferences', () => ({
  useUpdatePreferences: () => ({ updatePreferences, isUpdating: false }),
}))
const refresh = vi.fn(async () => undefined)
vi.mock('../../api/use-quick-views', () => ({ refreshFindingQuickViews: () => refresh() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('InformationalChip', () => {
  beforeEach(() => {
    countState.total = 7
    updatePreferences.mockClear()
  })

  it('says how many are hidden and counts with the list filter, informational only', () => {
    const onChange = vi.fn()
    render(
      <InformationalChip
        filters={{ state: 'open', informational: false }}
        hidden
        shownForView={false}
        onChange={onChange}
      />
    )
    expect(screen.getByTestId('informational-chip')).toHaveTextContent('Informational hidden (7)')
    expect(countState.lastFilters).toMatchObject({ state: 'open', informational: true })
    fireEvent.click(screen.getByRole('button', { name: 'Show' }))
    expect(onChange).toHaveBeenCalledWith(false)
  })

  it("uses the open view's own count and sends no request", () => {
    render(
      <InformationalChip
        filters={{}}
        hidden
        shownForView={false}
        knownCount={3}
        onChange={vi.fn()}
      />
    )
    expect(countState.enabled).toBe(false)
    expect(screen.getByTestId('informational-chip')).toHaveTextContent('Informational hidden (3)')
  })

  it('shows nothing when nothing is left out', () => {
    countState.total = 0
    const { container } = render(
      <InformationalChip filters={{}} hidden shownForView={false} onChange={vi.fn()} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('after Show, offers Hide and Always show (saved as the preference)', async () => {
    const onChange = vi.fn()
    render(<InformationalChip filters={{}} hidden={false} shownForView onChange={onChange} />)
    expect(countState.enabled).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Hide' }))
    expect(onChange).toHaveBeenCalledWith(true)
    fireEvent.click(screen.getByRole('button', { name: 'Always show' }))
    await waitFor(() =>
      expect(updatePreferences).toHaveBeenCalledWith({ findings_informational: 'include' })
    )
    await waitFor(() => expect(screen.queryByTestId('informational-chip')).toBeNull())
  })

  it('is not shown when the list shows them by default', () => {
    const { container } = render(
      <InformationalChip filters={{}} hidden={false} shownForView={false} onChange={vi.fn()} />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
