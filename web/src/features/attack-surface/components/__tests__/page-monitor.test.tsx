/**
 * Attack surface › Page changes (RFC-138): changes with their summary, the
 * diff sheet (values from the page shown as text only), watches with their
 * derived scripts and state, adding a watch, and no write controls without
 * scans:write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
    usePermissions: () => ({
      can: (p: string) => (p === actual.Permission.ScansWrite ? perms.write : true),
    }),
  }
})
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['attack_surface'], isLoading: false }),
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_k: string, d: string) => [d, vi.fn()],
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { PageMonitor } = await import('../page-monitor')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const now = new Date().toISOString()
const watches = {
  max: 200,
  items: [
    {
      id: 'w1',
      asset_id: 'a1',
      url: 'https://shop.example.com/login',
      mode: 'js',
      source: 'manual',
      enabled: true,
      cadence_hours: 24,
      ignore_patterns: [],
      dynamic: false,
      state: 'waiting',
      next_due_at: now,
      changes: 1,
      scripts: 2,
      created_at: now,
      updated_at: now,
    },
    {
      id: 'w2',
      asset_id: 'a1',
      parent_id: 'w1',
      url: 'https://shop.example.com/static/app.js',
      mode: 'js',
      source: 'derived',
      enabled: true,
      cadence_hours: 24,
      ignore_patterns: [],
      dynamic: false,
      state: 'ok',
      next_due_at: now,
      changes: 0,
      scripts: 0,
      created_at: now,
      updated_at: now,
    },
  ],
}
const hostile = 'https://skimmer.example.net/c.js?‮gnp.<img src=x onerror=alert(1)>'
const change = {
  id: 'c1',
  watch_id: 'w1',
  asset_id: 'a1',
  url: 'https://shop.example.com/login',
  detected_at: now,
  severity: 'high',
  muted: false,
  summary: {
    scripts_added: 1,
    scripts_removed: 0,
    third_party_added: 1,
    new_third_party_hosts: 1,
    content_changed: false,
    urls_added: 0,
    urls_removed: 0,
    lines_added: 0,
    lines_removed: 0,
  },
}
const detail = {
  ...change,
  diff: {
    kind: 'html',
    size_from: 10,
    size_to: 12,
    new_third_party_hosts: ['skimmer.example.net'],
    scripts_added: [{ id: 's', src: hostile, host: 'skimmer.example.net', third_party: true }],
  },
}

function routeGet() {
  api.get.mockImplementation((url: string) => {
    if (url.includes('/changes/c1')) return Promise.resolve(detail)
    if (url.includes('/changes?')) return Promise.resolve({ items: [change], total: 1 })
    if (url.endsWith('/watches')) return Promise.resolve(watches)
    if (url.endsWith('/suggestions'))
      return Promise.resolve({
        items: [
          {
            url: 'https://shop.example.com/',
            asset_id: 'a1',
            asset_name: 'https://shop.example.com',
            reason: 'root',
            mode: 'js',
          },
        ],
      })
    return Promise.reject(new Error('unexpected ' + url))
  })
}

describe('PageMonitor', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.write = true
    routeGet()
  })

  it('lists changes with their summary and opens the diff as plain text', async () => {
    wrap(<PageMonitor />)
    const list = await screen.findByTestId('page-changes')
    expect(within(list).getByText('1 new third-party host(s)')).toBeInTheDocument()
    await userEvent.click(within(list).getByRole('button', { name: /Open the change of/ }))
    const sheet = await screen.findByTestId('page-change-sheet')
    expect(within(sheet).getByTestId('diff-new-hosts')).toHaveTextContent('skimmer.example.net')
    const added = within(sheet).getByTestId('diff-scripts-added')
    // Markup from the page stays characters; the bidi override is made visible.
    expect(added.querySelector('img')).toBeNull()
    expect(added.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(added.textContent).not.toContain('‮')
    expect(within(added).getByText('No integrity check')).toBeInTheDocument()
    expect(sheet.querySelector('a[href]')).toBeNull()
  })

  it('shows watches with their state and derived scripts, and the waiting note', async () => {
    wrap(<PageMonitor />)
    const rows = await screen.findAllByTestId('page-watch')
    expect(rows).toHaveLength(1)
    expect(within(rows[0]).getByText('Waiting')).toBeInTheDocument()
    expect(screen.getByTestId('page-monitor-waiting')).toBeInTheDocument()
    await userEvent.click(
      within(rows[0]).getByRole('button', { name: /1 script\(s\) of this page/ })
    )
    expect(within(rows[0]).getByTestId('page-watch-scripts')).toHaveTextContent('/static/app.js')
  })

  it('adds a watch', async () => {
    api.post.mockResolvedValue({})
    wrap(<PageMonitor />)
    await screen.findAllByTestId('page-watch')
    await userEvent.type(
      screen.getByLabelText('URL of one of your web services'),
      'https://shop.example.com/cart'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Watch' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/page-monitoring/watches', {
        url: 'https://shop.example.com/cart',
        mode: 'js',
        source: 'manual',
      })
    )
  })

  it('hides every write control without scans:write', async () => {
    perms.write = false
    wrap(<PageMonitor />)
    const rows = await screen.findAllByTestId('page-watch')
    expect(screen.queryByLabelText('URL of one of your web services')).toBeNull()
    expect(within(rows[0]).queryByRole('switch')).toBeNull()
    expect(within(rows[0]).queryByRole('button', { name: /Stop watching/ })).toBeNull()
  })
})
