import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScopeExclusionsTable } from '../scope-exclusions-table'

const listCalls: Array<Record<string, unknown>> = []
vi.mock('../../api/use-scope-api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api/use-scope-api')>()),
  useScopeExclusionsApi: (params: Record<string, unknown>) => {
    listCalls.push(params)
    return { data: { data: [], total: 0 }, isLoading: false }
  },
  useScopeSettingsApi: () => ({ data: undefined }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// Radix Select needs these in jsdom.
Element.prototype.scrollIntoView ??= vi.fn()
Element.prototype.hasPointerCapture ??= vi.fn(() => false)
Element.prototype.releasePointerCapture ??= vi.fn()

const query = (status: string) => ({ search: '', kind: 'all', status, page: 1, perPage: 25 })
const props = {
  searchInput: '',
  onSearchInput: vi.fn(),
  onKindChange: vi.fn(),
  onPagination: vi.fn(),
}

describe('scope exclusions status filter', () => {
  it('shows a status control so the strip tile filter can be cleared', async () => {
    const onStatusChange = vi.fn()
    render(
      <ScopeExclusionsTable {...props} query={query('active')} onStatusChange={onStatusChange} />
    )
    const select = screen.getByRole('combobox', { name: /filter by status/i })
    await userEvent.setup().click(select)
    await userEvent.setup().click(await screen.findByRole('option', { name: 'All statuses' }))
    expect(onStatusChange).toHaveBeenCalledWith('all')
  })

  it('counts the status filter as an active filter in the empty state', () => {
    render(<ScopeExclusionsTable {...props} query={query('active')} onStatusChange={vi.fn()} />)
    expect(screen.getByText('No exclusions match')).toBeInTheDocument()
  })

  it('shows the plain empty state with no filter', () => {
    render(<ScopeExclusionsTable {...props} query={query('all')} onStatusChange={vi.fn()} />)
    expect(screen.getByText('Nothing is excluded')).toBeInTheDocument()
  })
})
