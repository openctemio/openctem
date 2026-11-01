import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { I18nProvider } from '@/context/i18n-provider'
import { DashboardHome } from '../components/dashboard-home'
import { DASHBOARD_CHOICE_KEY } from '../landing'

// The real hooks and the real SWR cache, with only the HTTP client faked:
// the home must read the dashboards with ONE request and seed the keys the
// rest of the page reads.

const http = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => ({
  get: http.get,
  post: http.post,
  put: http.put,
  del: http.del,
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), info: vi.fn(), error: vi.fn() } }))
vi.mock('next/dynamic', () => ({ default: () => () => null }))
vi.mock('@/lib/permissions', () => ({
  Permission: {
    DashboardsOrgView: 'dashboards:org:view',
    DashboardsOrgManage: 'dashboards:org:manage',
  },
  // The bootstrap has not arrived: the page must not depend on it.
  usePermissions: () => ({ can: () => false, canAny: () => false }),
}))

const widget = {
  widget_type: 'metric',
  x: 0,
  y: 0,
  w: 6,
  h: 1,
  config: {
    v: 2,
    id: 'w_open',
    data: { kind: 'metric', metric: 'findings.open', filter: {}, time: {} },
    viz: { type: 'stat', options: {} },
  },
}
const dash = (id: string, name: string, extra = {}) => ({
  id,
  name,
  is_default: false,
  layout: [widget],
  columns: 2,
  flow_panel_at: '2026-10-01T00:00:00Z',
  ...extra,
})
const figures = (scope: string) => ({
  dashboard_id: 'x',
  scope,
  restricted: false,
  facts_built_at: '2026-10-21T08:00:00Z',
  computed_at: new Date().toISOString(),
  refresh_schedule: 'manual',
  stale: false,
  widgets: [
    {
      id: 'w_open',
      index: 0,
      widget_type: 'metric',
      state: 'ready',
      shape: 'scalar',
      metric: 'findings.open',
      scalar: { value: 42 },
    },
  ],
})

function renderHome() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <I18nProvider locale="en">
        <DashboardHome />
      </I18nProvider>
    </SWRConfig>
  )
}

describe('DashboardHome request count', () => {
  beforeEach(() => {
    window.localStorage.clear()
    vi.clearAllMocks()
  })

  it('opens with one dashboard request and shows the figures', async () => {
    http.get.mockResolvedValue({
      personal: [dash('p1', 'Mine')],
      organization: [dash('o1', 'Org', { is_org_default: true })],
      landing: { kind: 'organization', id: 'o1' },
      data: figures('organization'),
    })
    renderHome()
    await waitFor(() => expect(screen.getByText('42')).toBeTruthy())
    expect(http.get.mock.calls.map((c) => c[0])).toEqual(['/api/v1/me/dashboards/home'])
  })

  it('sends the remembered choice and still makes one request', async () => {
    window.localStorage.setItem(DASHBOARD_CHOICE_KEY, 'personal:p1')
    http.get.mockResolvedValue({
      personal: [dash('p1', 'Mine')],
      landing: { kind: 'personal', id: 'p1' },
      data: figures('personal'),
    })
    renderHome()
    await waitFor(() => expect(screen.getByText('42')).toBeTruthy())
    expect(http.get.mock.calls.map((c) => c[0])).toEqual([
      '/api/v1/me/dashboards/home?choice=personal%3Ap1',
    ])
  })

  it('falls back to the per-dashboard reads when the home read fails', async () => {
    http.get.mockImplementation((url: string) => {
      if (url.endsWith('/home')) return Promise.reject(new Error('boom'))
      if (url === '/api/v1/me/dashboards') return Promise.resolve({ data: [dash('p1', 'Mine')] })
      if (url === '/api/v1/me/dashboards/p1/data') return Promise.resolve(figures('personal'))
      return Promise.reject(new Error(`unexpected ${url}`))
    })
    renderHome()
    await waitFor(() => expect(screen.getByText('42')).toBeTruthy())
  })
})
