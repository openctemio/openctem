/**
 * The "From scope" source of the target picker: active in-scope entries
 * only, read only by people who can read the scope, a wildcard picked as a
 * *.domain target, entries that are not one target not pickable, expiring
 * entries flagged, and "Add all in-scope entries" across pages.
 */
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
const canRead = vi.hoisted(() => ({ value: true }))
vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => get(...a),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => canRead.value }),
  useHasPermission: () => canRead.value,
}))
vi.mock('sonner', () => ({ toast: { warning: vi.fn(), error: vi.fn() } }))

import { ScopeSource } from '../target-picker/scope-source'

const soon = new Date(Date.now() + 2 * 86_400_000).toISOString()
const ENTRIES = [
  { id: '1', target_type: 'domain', pattern: '*.example.com', status: 'active' },
  {
    id: '2',
    target_type: 'ip_range',
    pattern: '203.0.113.0/24',
    status: 'active',
    expires_at: soon,
  },
  { id: '3', target_type: 'domain', pattern: 'api-*.example.com', status: 'active' },
  { id: '4', target_type: 'ip_address', pattern: '198.51.100.7', status: 'active' },
]

function renderSource(present: string[] = [], onChange = vi.fn()) {
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <ScopeSource present={new Set(present)} onChange={onChange} />
    </SWRConfig>
  )
  return onChange
}

describe('ScopeSource', () => {
  beforeEach(() => {
    get.mockReset()
    canRead.value = true
  })

  it('lists only active in-scope domains, addresses and ranges; never reads exclusions', async () => {
    get.mockResolvedValue({ data: ENTRIES, total: 4 })
    renderSource(['198.51.100.7'])
    expect(await screen.findByText('*.example.com')).toBeInTheDocument()
    const url = new URL(String(get.mock.calls[0][0]), 'http://x')
    expect(url.pathname).toBe('/api/v1/scope/targets')
    expect(url.searchParams.get('statuses')).toBe('active')
    expect(url.searchParams.get('types')).toBe('domain,subdomain,ip_address,ip_range')
    expect(get.mock.calls.some((c) => String(c[0]).includes('/scope/exclusions'))).toBe(false)
    // Already in the scan: checked.
    expect(screen.getByRole('checkbox', { name: '198.51.100.7' })).toBeChecked()
  })

  it('picks a wildcard as a *.domain target and a range as itself', async () => {
    get.mockResolvedValue({ data: ENTRIES, total: 4 })
    const user = userEvent.setup()
    const onChange = renderSource()
    await user.click(await screen.findByRole('checkbox', { name: '*.example.com' }))
    expect(onChange).toHaveBeenLastCalledWith(['*.example.com'], true)
    await user.click(screen.getByRole('checkbox', { name: '203.0.113.0/24' }))
    expect(onChange).toHaveBeenLastCalledWith(['203.0.113.0/24'], true)
  })

  it('does not let a name pattern be picked, and flags an entry about to expire', async () => {
    get.mockResolvedValue({ data: ENTRIES, total: 4 })
    renderSource()
    expect(await screen.findByRole('checkbox', { name: 'api-*.example.com' })).toBeDisabled()
    expect(screen.getByText(/A name pattern or an address span/)).toBeInTheDocument()
    expect(screen.getByText(/Expires in 2 days: later runs will refuse it/)).toBeInTheDocument()
  })

  it('reads nothing for someone who cannot read the scope', () => {
    canRead.value = false
    renderSource()
    expect(get).not.toHaveBeenCalled()
    expect(screen.getByText(/needs the scope read permission/)).toBeInTheDocument()
  })

  it('adds every in-scope entry across pages, without repeats or what is already there', async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({
      id: `p1-${i}`,
      target_type: 'ip_address',
      pattern: `10.0.0.${i}`,
      status: 'active',
    }))
    const page2 = [
      { id: 'p2-0', target_type: 'domain', pattern: '*.example.com', status: 'active' },
      { id: 'p2-1', target_type: 'domain', pattern: 'api-*.example.com', status: 'active' },
      { id: 'p2-2', target_type: 'ip_address', pattern: '10.0.0.1', status: 'active' },
    ]
    get.mockImplementation((u: string) => {
      const page = new URL(u, 'http://x').searchParams.get('page')
      return Promise.resolve(
        page === '2' ? { data: page2, total: 103 } : { data: page1, total: 103 }
      )
    })
    const user = userEvent.setup()
    const onChange = renderSource(['10.0.0.0'])
    await user.click(await screen.findByTestId('scope-add-all'))
    await waitFor(() => expect(onChange).toHaveBeenCalled())
    const [added, picked] = onChange.mock.calls.at(-1) as [string[], boolean]
    expect(picked).toBe(true)
    expect(added).toHaveLength(100) // 99 new addresses + the wildcard
    expect(added).toContain('*.example.com')
    expect(added).not.toContain('10.0.0.0')
    expect(added).not.toContain('api-*.example.com')
    expect(within(document.body).queryByText('Could not load the in-scope entries')).toBeNull()
  })
})
