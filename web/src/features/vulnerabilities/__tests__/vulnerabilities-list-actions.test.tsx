import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { VulnerabilitiesList } from '../components/list/vulnerabilities-list'
import { retestSummary, selectionTaskParams } from '../components/actions/use-vuln-actions'
import type { VulnListItem, VulnListResponse } from '../types/list'
import { buildVulnListQuery, readList, readViewId, vulnActionParams } from '../lib/vuln-list'
import { batchSourceHref } from '@/features/findings/components/group-exceptions-panel'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  ...api,
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => window.location.pathname,
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({
    can: (p: string) => perms.granted.has(p),
    canAny: (...ps: string[]) => ps.some((p) => perms.granted.has(p)),
  }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({ useModuleEnabled: () => true }))
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
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), warning: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.scrollIntoView ??= () => {}

const READ = ['findings:vulnerabilities:read', 'findings:read']
const ACT = ['findings:write', 'findings:verify', 'findings:export']

const row = (cve: string): VulnListItem => ({
  cve_id: cve,
  in_catalog: true,
  title: `Title of ${cve}`,
  aliases: [],
  severity: 'high',
  kev: false,
  kev_ransomware: false,
  exploit: false,
  exploit_maturity: '',
  worst_priority: 'P1',
  findings: 2,
  open_findings: 2,
  assets: 1,
  internet_facing_assets: 0,
  crown_jewel_assets: 0,
  products: [],
  fixed_versions: [],
  has_fix: false,
  past_sla: 0,
  in_task: 0,
  first_seen_at: '2026-10-01T00:00:00Z',
  last_seen_at: '2026-10-26T00:00:00Z',
})

const page = (rows: VulnListItem[]): VulnListResponse => ({
  data: rows,
  total: rows.length,
  page: 1,
  per_page: 25,
  total_pages: 1,
  summary: { total: rows.length, kev: 0, exploit: 0, emerging: 0, past_sla: 0 },
})

const renderList = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <VulnerabilitiesList />
    </SWRConfig>
  )

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  api.get.mockResolvedValue(page([row('CVE-2024-3094'), row('CVE-2023-44487')]))
  window.history.replaceState(null, '', '/vulnerabilities?severity=high')
})
afterEach(() => vi.restoreAllMocks())

describe('bulk actions on the vulnerabilities list', () => {
  it('offers no selection without an action permission', async () => {
    perms.granted = new Set(READ)
    renderList()
    await screen.findByText('Title of CVE-2024-3094')
    expect(screen.queryByRole('checkbox', { name: /select/i })).toBeNull()
  })

  it('retests the open findings of the selected rows with the list filters', async () => {
    perms.granted = new Set([...READ, ...ACT])
    api.post.mockResolvedValue({
      open_findings: 3,
      attempted: 3,
      counts: { queued: 2, not_eligible: 1 },
      items: [],
    })
    renderList()
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select CVE-2024-3094' }))
    const bar = await screen.findByRole('toolbar', { name: /selected rows/i })
    expect(bar).toHaveTextContent('1')
    await userEvent.click(screen.getByRole('button', { name: 'Retest' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Retest' }))
    await waitFor(() => expect(api.post).toHaveBeenCalled())
    const [url, body] = api.post.mock.calls[0]
    expect(url).toBe('/api/v1/vulnerability-exposures/retests')
    expect(body.cve_ids).toEqual(['CVE-2024-3094'])
    const params = new URLSearchParams(body.params)
    expect(params.get('severity')).toBe('high')
    expect(params.has('page')).toBe(false)
    // Never a tenant or a scope in the body.
    expect(Object.keys(body).sort()).toEqual(['cve_ids', 'params'])
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
  })

  it('opens the exception dialog over the selection', async () => {
    perms.granted = new Set([...READ, ...ACT])
    renderList()
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select CVE-2023-44487' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Accept risk' }))
    expect(await screen.findByRole('dialog')).toHaveTextContent(/CVE-2023-44487/)
  })

  it('exports the findings behind the rows under the current filters', async () => {
    perms.granted = new Set([...READ, ...ACT])
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('id,title\n', { status: 200 }))
    URL.createObjectURL ??= () => 'blob:x'
    URL.revokeObjectURL ??= () => {}
    renderList()
    await screen.findByText('Title of CVE-2024-3094')
    await userEvent.click(screen.getByRole('button', { name: 'Export CSV' }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://x')
    expect(url.pathname).toMatch(/\/api\/v1\/vulnerability-exposures\/export$/)
    expect(url.searchParams.get('severity')).toBe('high')
    expect(url.searchParams.get('format')).toBe('csv')
    expect(url.searchParams.has('cve_id')).toBe(false)
  })
})

describe('vulnerability action helpers', () => {
  it('builds the task query from the selection: open findings, findings filters only', () => {
    const q = new URLSearchParams(
      selectionTaskParams({
        cveIds: ['CVE-2024-3094'],
        params: 'severity=high&kev=true&view=x&state=all',
      })
    )
    expect(q.get('cve_id')).toBe('CVE-2024-3094')
    expect(q.get('state')).toBe('open')
    expect(q.get('severity')).toBe('high')
    expect(q.has('kev')).toBe(false)
    expect(q.has('view')).toBe(false)
  })

  it('summarizes a bulk retest', () => {
    const t = (_k: string, fb: string, v?: Record<string, unknown>) =>
      fb
        .replace(
          /\{count, plural, one \{# ([^}]*)\} other \{# ([^}]*)\}\}/,
          (_m, one, other) => `${v?.count} ${v?.count === 1 ? one : other}`
        )
        .replace('{count}', String(v?.count))
    const s = retestSummary(t as never, {
      open_findings: 60,
      attempted: 50,
      counts: { queued: 40, rate_limited: 10 },
      items: [],
    })
    expect(s.title).toBe('40 retests queued')
    expect(s.detail).toContain('10 wait for the retest limit')
    expect(s.detail).toContain('10 not tried')
  })

  it('keeps a saved view and only the lens the URL sets', () => {
    const id = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    const q = buildVulnListQuery(new URLSearchParams(`view=${id}`))
    expect(q.get('view')).toBe(id)
    expect(q.has('state')).toBe(false)
    expect(readViewId(new URLSearchParams('view=verify'))).toBeUndefined()
    expect(buildVulnListQuery(new URLSearchParams('')).get('state')).toBe('open')
    expect(vulnActionParams(new URLSearchParams('page=3&per_page=50&kev=true')).toString()).toBe(
      'state=open&kev=true'
    )
  })

  it('reads a CVE selection from the URL, dropping malformed ids', () => {
    expect(
      readList(new URLSearchParams('cve_id=cve-2024-3094,x%27--,CVE-2023-44487'), 'cve_id')
    ).toEqual(['CVE-2024-3094', 'CVE-2023-44487'])
  })

  it('links a group exception to where it was asked from', () => {
    expect(
      batchSourceHref({
        source_type: 'vulnerability_selection',
        source_id: 'x',
        source_title: 'CVE-2024-3094',
      })
    ).toBe('/vulnerabilities/CVE-2024-3094')
    expect(
      batchSourceHref({
        source_type: 'vulnerability_selection',
        source_id: 'x',
        source_title: 'CVE-2024-3094, CVE-2023-44487 +3',
      })
    ).toBe('/vulnerabilities?cve_id=CVE-2024-3094%2CCVE-2023-44487')
    expect(batchSourceHref({ source_type: 'remediation_task', source_id: 't1' })).toBe(
      '/remediation/tasks/t1'
    )
  })
})
