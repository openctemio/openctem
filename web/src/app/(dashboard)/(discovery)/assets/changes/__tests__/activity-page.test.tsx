/**
 * Assets > Activity: one page for what changed on assets. The kinds of
 * change are one segmented control with their counts (no metric strip), and
 * the Values kind shows the value feed without asking for the inventory
 * change list. A reader without assets:read sees the access message only.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const state = vi.hoisted(() => ({ view: 'appeared', canRead: true, listEnabled: [] as boolean[] }))
const setView = vi.fn((v: string) => {
  state.view = v
})

vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsRead: 'assets:read' },
  useHasPermission: () => state.canRead,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (key: string, def: string) =>
    key === 'view' ? [state.view, setView] : [def, vi.fn()],
}))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    pagination: { pageIndex: 0, pageSize: 20 },
    setPagination: vi.fn(),
    setPage: vi.fn(),
  }),
}))
vi.mock('@/features/assets/components/assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
}))
vi.mock('@/features/assets', () => ({
  RecentAssetChanges: () => <div data-testid="value-feed" />,
}))
vi.mock('@/features/asset-changes', () => ({
  isChangeView: (v: string) =>
    ['appeared', 'disappeared', 'newly_exposed', 'exposure_changes', 'shadow_it'].includes(v),
  useAssetChanges: (_v: string, _q: unknown, _p: unknown, enabled: boolean) => {
    state.listEnabled.push(enabled)
    return { changes: [], total: 0, error: undefined, isLoading: false, mutate: vi.fn() }
  },
  useAssetChangeCounts: () => ({
    counts: { appeared: 41, disappeared: 9, newly_exposed: 3, exposure_changes: 17, shadow_it: 8 },
    mutate: vi.fn(),
  }),
}))

import AssetChangesPage from '../page'

beforeEach(() => {
  state.view = 'appeared'
  state.canRead = true
  state.listEnabled = []
  setView.mockClear()
})

describe('Assets > Activity', () => {
  it('is titled Activity and lists the kinds with their counts, without a metric strip', () => {
    render(<AssetChangesPage />)
    expect(screen.getByRole('heading', { name: 'Activity' })).toBeInTheDocument()
    const kinds = screen.getByRole('radiogroup', { name: 'Kind of change' })
    for (const [name, n] of [
      ['Appeared', '41'],
      ['Disappeared', '9'],
      ['Shadow IT', '8'],
    ]) {
      expect(kinds).toHaveTextContent(name)
      expect(kinds).toHaveTextContent(n)
    }
    expect(kinds).toHaveTextContent('Values')
    expect(screen.queryByTestId('value-feed')).toBeNull()
  })

  it('choosing Values writes ?view=values', async () => {
    render(<AssetChangesPage />)
    await userEvent.click(screen.getByRole('radio', { name: /Values/ }))
    expect(setView).toHaveBeenCalledWith('values')
  })

  it('the Values kind shows the value feed and does not ask for the change list', () => {
    state.view = 'values'
    render(<AssetChangesPage />)
    expect(screen.getByTestId('value-feed')).toBeInTheDocument()
    expect(state.listEnabled.every((e) => e === false)).toBe(true)
    // The period applies to the inventory changes only.
    expect(screen.queryByRole('combobox', { name: 'Period' })).toBeNull()
  })

  it('a reader without assets:read sees only the access message', () => {
    state.canRead = false
    render(<AssetChangesPage />)
    expect(screen.getByText('Access denied')).toBeInTheDocument()
    expect(screen.queryByRole('radiogroup')).toBeNull()
  })
})
