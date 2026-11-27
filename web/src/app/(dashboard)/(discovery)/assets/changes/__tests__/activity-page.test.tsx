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

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/assets/changes',
  useSearchParams: () => new URLSearchParams(),
}))
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
  it('keeps the Assets title and filters by kind from a token in the toolbar, with counts', async () => {
    render(<AssetChangesPage />)
    // The section title stays on every Assets tab; the tab names the page.
    expect(screen.getByRole('heading', { name: 'Assets' })).toBeInTheDocument()
    // One tab row: the kind is a filter token, not a segmented row under the tabs.
    expect(screen.queryByRole('radiogroup')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Kind: Appeared' }))
    for (const [name, n] of [
      ['Appeared', '41'],
      ['Disappeared', '9'],
      ['Shadow IT', '8'],
    ]) {
      expect(
        await screen.findByRole('menuitemradio', { name: new RegExp(name) })
      ).toHaveTextContent(n)
    }
    expect(screen.getByRole('menuitemradio', { name: /Values/ })).toBeInTheDocument()
    expect(screen.queryByTestId('value-feed')).toBeNull()
  }, 15_000)

  it('choosing Values writes ?view=values', async () => {
    render(<AssetChangesPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Kind: Appeared' }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: /Values/ }))
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

  it('the title row names the kind and says the count once', () => {
    render(<AssetChangesPage />)
    expect(screen.getByRole('heading', { level: 2, name: 'Appeared' })).toBeInTheDocument()
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
  })

  it('the internet-facing toggle keeps its place, pressed and locked, for newly exposed', () => {
    state.view = 'newly_exposed'
    render(<AssetChangesPage />)
    const toggle = screen.getByRole('button', { name: 'Internet-facing only' })
    expect(toggle).toBeDisabled()
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
  })

  it('the internet-facing toggle is a toolbar button, not pressed at rest', () => {
    render(<AssetChangesPage />)
    const toggle = screen.getByRole('button', { name: 'Internet-facing only' })
    expect(toggle).toBeEnabled()
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    expect(toggle).toHaveAttribute('data-slot', 'internet-only-toggle')
  })

  it('a reader without assets:read sees only the access message', () => {
    state.canRead = false
    render(<AssetChangesPage />)
    expect(screen.getByText('You do not have access to asset activity')).toBeInTheDocument()
    expect(document.querySelector('[data-slot="list-title-row"]')).toBeNull()
    expect(screen.queryByRole('button', { name: /^Kind:/ })).toBeNull()
  })
})
