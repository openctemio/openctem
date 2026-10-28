import { beforeEach, describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { render, screen, waitFor, within } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { VulnerabilitiesList } from '../components/list/vulnerabilities-list'
import { WhereCard } from '../components/page/where-card'
import type { VulnListItem, VulnListResponse } from '../types/list'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const push = vi.hoisted(() => vi.fn())
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn() }),
  usePathname: () => window.location.pathname,
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
vi.mock('@/lib/permissions', async (orig) => {
  const real = await orig<typeof import('@/lib/permissions')>()
  return {
    ...real,
    usePermissions: () => ({
      can: (p: string) => perms.granted.has(p),
      canAny: (...ps: string[]) => ps.some((p) => perms.granted.has(p)),
    }),
  }
})
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/saved-views/api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('@/features/saved-views/api/use-saved-views')>()),
  useSavedViews: () => ({ views: [], mutate: vi.fn() }),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({ useMyGroups: () => ({ groups: [] }) }))
vi.mock('@/features/nav-pins/api/use-nav-pins', () => ({
  useNavPins: () => ({ pins: [], isPinned: () => false, toggle: vi.fn() }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'Org' } }),
}))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const READ = ['findings:vulnerabilities:read', 'findings:read']

function item(over: Partial<VulnListItem> = {}): VulnListItem {
  return {
    cve_id: 'CVE-2024-3094',
    in_catalog: true,
    title: 'Backdoor in xz <script>alert(1)</script>',
    aliases: ['GHSA-aaaa-bbbb-cccc'],
    severity: 'critical',
    cvss_score: 10,
    epss_score: 0.97,
    epss_percentile: 0.999,
    kev: true,
    kev_due_date: '2000-01-01T00:00:00Z',
    kev_ransomware: true,
    exploit: true,
    exploit_maturity: 'weaponized',
    emerging: { id: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b', level: 'immediate', state: 'new' },
    worst_priority: 'P0',
    findings: 9,
    open_findings: 8,
    assets: 12,
    internet_facing_assets: 4,
    crown_jewel_assets: 1,
    products: [{ name: 'xz-utils', versions: ['5.6.0', '5.6.1'], findings: 9 }],
    fixed_versions: ['5.6.2'],
    has_fix: true,
    past_sla: 2,
    in_task: 3,
    first_seen_at: '2026-10-01T00:00:00Z',
    last_seen_at: '2026-10-26T00:00:00Z',
    ...over,
  }
}

function page(rows: VulnListItem[], over: Partial<VulnListResponse> = {}): VulnListResponse {
  return {
    data: rows,
    total: rows.length,
    page: 1,
    per_page: 25,
    total_pages: 1,
    summary: { total: 128, kev: 7, exploit: 19, emerging: 2, past_sla: 12 },
    ...over,
  }
}

const renderList = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <VulnerabilitiesList />
    </SWRConfig>
  )

const lastListUrl = () =>
  [...api.get.mock.calls]
    .map((c) => c[0] as string)
    .filter((u) => u.startsWith('/api/v1/vulnerability-exposures?'))
    .pop() ?? ''

beforeEach(() => {
  api.get.mockReset()
  push.mockReset()
  perms.granted = new Set(READ)
  window.history.replaceState(null, '', '/vulnerabilities')
})

describe('VulnerabilitiesList', () => {
  it('lists one row per CVE with its signals, reach, fix and remediation, sorted by risk', async () => {
    api.get.mockResolvedValue(
      page([
        item(),
        item({
          cve_id: 'CVE-2023-44487',
          title: 'HTTP/2 Rapid Reset',
          kev: false,
          emerging: undefined,
          exploit: false,
          past_sla: 0,
          worst_priority: 'P1',
          fixed_versions: [],
          has_fix: false,
          in_task: 0,
          products: [],
          aliases: [],
        }),
      ])
    )
    renderList()
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Vulnerabilities' })
    ).toBeInTheDocument()
    await screen.findAllByRole('link', { name: 'Vulnerability page for CVE-2024-3094' })
    expect(lastListUrl()).toBe('/api/v1/vulnerability-exposures?state=open&page=1&per_page=25')

    // Feed text renders as text.
    expect(screen.getAllByText('Backdoor in xz <script>alert(1)</script>')[0]).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getAllByText('Weaponized')[0]).toBeInTheDocument()
    expect(screen.getAllByText('2 past SLA')[0]).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Emerging threat' })[0]).toHaveAttribute(
      'href',
      '/emerging-threats/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    )
    expect(
      screen.getAllByRole('link', { name: /12 assets: open the findings by asset/ })[0]
    ).toHaveAttribute('href', '/findings?cve_id=CVE-2024-3094&state=open&group=asset_id')
    expect(screen.getAllByText('5.6.2')[0]).toBeInTheDocument()
    expect(screen.getAllByText('3 of 8 in tasks')[0]).toBeInTheDocument()
    expect(screen.getAllByText('No fix yet')[0]).toBeInTheDocument()
    expect(screen.getAllByText('Not in a task')[0]).toBeInTheDocument()
    expect(screen.getByText(/Counts are in your data scope/)).toBeInTheDocument()
  })

  it('every strip tile is a filter that reaches the request', async () => {
    api.get.mockResolvedValue(page([item()]))
    renderList()
    const tile = await screen.findByRole('button', { name: /Known exploited/ })
    await userEvent.click(tile)
    await waitFor(() => expect(lastListUrl()).toContain('kev=true'))
    expect(window.location.search).toContain('kev=true')
    // The chip removes it again.
    await userEvent.click(
      await screen.findByRole('button', { name: 'Remove filter Known exploited' })
    )
    await waitFor(() => expect(window.location.search).not.toContain('kev=true'))
  })

  it('opens the vulnerability page from a row', async () => {
    api.get.mockResolvedValue(page([item()]))
    renderList()
    const title = await screen.findAllByText('Backdoor in xz <script>alert(1)</script>')
    await userEvent.click(title[0])
    expect(push).toHaveBeenCalledWith('/vulnerabilities/CVE-2024-3094')
  })

  it('reads its filters from the URL', async () => {
    window.history.replaceState(
      null,
      '',
      '/vulnerabilities?severity=high&has_fix=false&sort=-epss&state=all'
    )
    api.get.mockResolvedValue(page([]))
    renderList()
    await waitFor(() =>
      expect(lastListUrl()).toBe(
        '/api/v1/vulnerability-exposures?state=all&severity=high&has_fix=false&sort=-epss&page=1&per_page=25'
      )
    )
    expect(await screen.findByText('No vulnerability matches these filters')).toBeInTheDocument()
    expect(
      screen.getByText('No fix yet', { selector: '[data-testid="filter-chip"] *' })
    ).toBeInTheDocument()
  })

  it('shows the first-run empty state without filters', async () => {
    api.get.mockResolvedValue(
      page([], { summary: { total: 0, kev: 0, exploit: 0, emerging: 0, past_sla: 0 } })
    )
    renderList()
    expect(
      await screen.findByText('No open vulnerabilities on the assets you can see')
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Browse the CVE catalog' })).toHaveAttribute(
      'href',
      '/exposures/vulnerabilities?tab=catalog'
    )
  })

  it('shows the error in place with a retry', async () => {
    api.get.mockRejectedValue(Object.assign(new Error('boom'), { statusCode: 500 }))
    renderList()
    expect(await screen.findByRole('button', { name: /Retry|Try again/ })).toBeInTheDocument()
  })

  it('without findings:read it says so and sends no request', async () => {
    perms.granted = new Set(['findings:vulnerabilities:read'])
    renderList()
    expect(await screen.findByText(/the vulnerabilities list/)).toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('WhereCard targets', () => {
  it('shows where on the asset the findings point, as text', async () => {
    api.get.mockResolvedValue({
      data: [
        {
          asset_id: 'a1',
          name: 'web-01.example.com',
          asset_type: 'host',
          criticality: 'high',
          crown_jewel: false,
          internet_facing: true,
          owner: '',
          open_findings: 1,
          total_findings: 1,
          worst_priority: 'P0',
          worst_severity: 'critical',
          targets: ['443/tcp', '/login?next=<b>x</b>'],
          targets_more: true,
        },
      ],
      total: 1,
      page: 1,
      per_page: 10,
      total_pages: 1,
    })
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <WhereCard cve="CVE-2024-3094" impacted={1} />
      </SWRConfig>
    )
    const list = await screen.findByRole('list', { name: 'Where on the asset' })
    expect(within(list).getByText('443/tcp')).toBeInTheDocument()
    expect(within(list).getByText('/login?next=<b>x</b>')).toBeInTheDocument()
    expect(within(list).getByText('and more')).toBeInTheDocument()
    expect(within(list).queryByRole('link')).toBeNull()
  })
})
