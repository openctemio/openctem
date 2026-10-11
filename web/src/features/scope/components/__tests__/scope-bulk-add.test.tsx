/**
 * Pasting a list into scope and adding the addresses behind in-scope names
 * (RFC-054 §14): one bulk request each, with every line's outcome.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) => p !== actual.Permission.ScopeWrite || perms.write,
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopeBulkAddDialog, parseScopeList } = await import('../scope-bulk-add-dialog')
const { ScopeAddressSuggestions } = await import('../scope-address-suggestions')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  perms.write = true
})

describe('parseScopeList', () => {
  it('detects each kind, drops duplicates and names what it cannot read', () => {
    const { items, unrecognized } = parseScopeList(
      '*.Example.com\napi.example.org, 203.0.113.0/24\n203.0.113.9 api.example.org not_a_target'
    )
    expect(items).toEqual([
      { target_type: 'domain', pattern: '*.example.com' },
      { target_type: 'domain', pattern: 'api.example.org' },
      { target_type: 'ip_range', pattern: '203.0.113.0/24' },
      { target_type: 'ip_address', pattern: '203.0.113.9' },
    ])
    expect(unrecognized).toEqual(['not_a_target'])
  })
})

describe('ScopeBulkAddDialog', () => {
  it('adds the list in one request and lists every outcome', async () => {
    api.post.mockResolvedValue({
      results: [
        { target_type: 'domain', pattern: 'a.example.com', result: 'created', status: 'active' },
        {
          target_type: 'domain',
          pattern: 'x.gov',
          result: 'refused',
          code: 'DENY_LIST',
          message: 'Not allowed.',
        },
      ],
      created: 1,
      existing: 0,
      refused: 1,
    })
    wrap(<ScopeBulkAddDialog open onOpenChange={() => {}} />)
    fireEvent.change(screen.getByLabelText('Targets'), { target: { value: 'a.example.com x.gov' } })
    expect(screen.getByText(/2 to add/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() => expect(screen.getByTestId('scope-list-results')).toBeInTheDocument())
    expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/bulk', {
      items: [
        { target_type: 'domain', pattern: 'a.example.com' },
        { target_type: 'domain', pattern: 'x.gov' },
      ],
    })
    expect(screen.getByText('refused: Not allowed.')).toBeInTheDocument()
  })
})

describe('ScopeAddressSuggestions', () => {
  it('offers the addresses and adds the picked ones as exact entries', async () => {
    api.get.mockResolvedValue({
      data: [
        { address: '203.0.113.9', asset_id: 'a1', names: ['www.example.com'], provider: 'Amazon' },
        { address: '203.0.113.10', asset_id: 'a2', names: ['api.example.com'] },
      ],
      skipped_shared: 2,
    })
    api.post.mockResolvedValue({ results: [], created: 1, existing: 0, refused: 0 })
    wrap(<ScopeAddressSuggestions />)
    await userEvent.click(await screen.findByRole('button', { name: 'Review' }))
    expect(screen.getByText('2 shared addresses are not listed.')).toBeInTheDocument()
    await userEvent.click(screen.getByLabelText(/203\.0\.113\.10/))
    await userEvent.click(screen.getByRole('button', { name: 'Add 1 to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/bulk', {
        items: [{ target_type: 'ip_address', pattern: '203.0.113.9' }],
      })
    )
  })

  it('shows nothing without scope:write', () => {
    perms.write = false
    wrap(<ScopeAddressSuggestions />)
    expect(api.get).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Review' })).toBeNull()
  })
})
