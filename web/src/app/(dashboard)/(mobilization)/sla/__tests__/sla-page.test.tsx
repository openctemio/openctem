/**
 * The SLA compliance page counts on the server over the Findings population:
 * every tile equals the total of the Findings list its link opens, also
 * above the 100 rows the page used to score in the browser, and a failed
 * read shows an error and "—", never zeros.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within, fireEvent } from '@testing-library/react'
import { SWRConfig } from 'swr'

const push = vi.fn()
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
  usePathname: () => '/sla',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'T' } }),
}))
vi.mock('@/lib/api/error-handler', () => ({ handleApiError: vi.fn() }))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

type F = {
  id: string
  title: string
  severity: string
  status: string
  sla_status: string
  daysPast: number
}

// 130 past due (more than the 100 the page used to score), 7 due soon, 18 on
// track, 6 without an SLA, one closed past due and one pentest draft.
const DATA: F[] = []
let n = 0
const add = (count: number, p: Partial<F>) => {
  for (let i = 0; i < count; i++)
    DATA.push({
      id: `f${n++}`,
      title: `finding ${n}`,
      severity: 'high',
      status: 'new',
      sla_status: 'on_track',
      daysPast: 0,
      ...p,
    })
}
add(60, { sla_status: 'overdue', daysPast: 3, severity: 'critical' })
add(40, { sla_status: 'exceeded', daysPast: 20 })
add(20, { sla_status: 'overdue', daysPast: 60, severity: 'medium' })
add(10, { sla_status: 'exceeded', daysPast: 200 })
add(7, { sla_status: 'warning' })
add(18, { sla_status: 'on_track' })
add(6, { sla_status: 'not_applicable' })
add(1, { sla_status: 'overdue', status: 'resolved', daysPast: 5 })
add(1, { sla_status: 'overdue', status: 'draft', daysPast: 5 })

const OPEN = new Set(['new', 'confirmed', 'in_progress', 'fix_applied'])
const days = (iso: string) => Number(/P(\d+)D/.exec(iso)![1])

/** The server: the same filter semantics for the list, the stats and the page's links. */
function select(q: URLSearchParams): F[] {
  return DATA.filter((f) => {
    if (q.get('state') === 'open' && !OPEN.has(f.status)) return false
    const sla = q.get('sla_status')
    if (sla && !sla.split(',').includes(f.sla_status)) return false
    const sev = q.get('severity')
    if (sev && !sev.split(',').includes(f.severity)) return false
    const gt = q.get('sla_deadline_gt')
    if (gt && !(f.daysPast < days(gt))) return false
    const lte = q.get('sla_deadline_lte')
    if (lte && !(f.daysPast >= days(lte))) return false
    return true
  })
}

let failStats = false
vi.mock('@/lib/api/client', () => ({
  get: vi.fn(async (url: string) => {
    const [path, qs = ''] = url.split('?')
    const q = new URLSearchParams(qs)
    const rows = select(q)
    if (path.endsWith('/findings/stats')) {
      if (failStats) throw new Error('boom')
      const by_severity: Record<string, number> = {}
      for (const r of rows) by_severity[r.severity] = (by_severity[r.severity] ?? 0) + 1
      if (q.get('sla_breakdown') !== 'true') return { total: rows.length, by_severity }
      const past = rows.filter((r) => ['overdue', 'exceeded'].includes(r.sla_status))
      const inAge = (lo: number, hi: number) =>
        past.filter((r) => r.daysPast >= lo && r.daysPast < hi).length
      const past_due_by_severity: Record<string, number> = {}
      for (const r of past)
        past_due_by_severity[r.severity] = (past_due_by_severity[r.severity] ?? 0) + 1
      return {
        total: rows.length,
        by_severity,
        sla: {
          past_due: past.length,
          due_soon: rows.filter((r) => r.sla_status === 'warning').length,
          on_track: rows.filter((r) => r.sla_status === 'on_track').length,
          past_due_by_age: {
            up_to_7: inAge(0, 7),
            d8_to_30: inAge(7, 30),
            d31_to_90: inAge(30, 90),
            over_90: inAge(90, Infinity),
          },
          past_due_by_severity,
        },
      }
    }
    const page = Number(q.get('page') ?? 1)
    const per = Number(q.get('per_page') ?? 20)
    return {
      data: rows.slice((page - 1) * per, page * per).map((r) => ({ ...r, message: r.title })),
      total: rows.length,
      page,
      per_page: per,
    }
  }),
}))

import SlaCompliancePage from '../page'

function renderPage() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <SlaCompliancePage />
    </SWRConfig>
  )
}

/** The count a Findings page shows for the filter in a link. */
function drilldownTotal(href: string): number {
  const u = new URL(href, 'http://x')
  expect(u.pathname).toBe('/findings')
  return select(u.searchParams).length
}

beforeEach(() => {
  push.mockClear()
  failStats = false
})

describe('SLA compliance page', () => {
  it('reads every number in one stats request', async () => {
    const { get } = await import('@/lib/api/client')
    vi.mocked(get).mockClear()
    renderPage()
    await screen.findByText('How long past due')
    await waitFor(() => expect(screen.getAllByText('130').length).toBeGreaterThan(0))
    const stats = vi.mocked(get).mock.calls.filter(([u]) => String(u).includes('/findings/stats'))
    expect(stats).toHaveLength(1)
    expect(String(stats[0][0])).toContain('sla_breakdown=true')
  })

  it('each tile equals the total of the Findings list it opens, above 100 findings', async () => {
    renderPage()
    const expected: Record<string, number> = {
      'Past due': 130,
      'Due soon': 7,
      'On track': 18,
      'Open findings': 161,
    }
    for (const [label, want] of Object.entries(expected)) {
      const dt = await screen.findByText(label, { selector: 'dt' })
      const cell = dt.closest('button') as HTMLElement
      await waitFor(() => expect(within(cell).getByText(String(want))).toBeTruthy())
      fireEvent.click(cell)
      const href = push.mock.calls.at(-1)![0] as string
      expect(drilldownTotal(href), `${label} -> ${href}`).toBe(want)
    }
  })

  it('the aging buckets add up to the Past due tile', async () => {
    renderPage()
    await screen.findByText('How long past due')
    const want = { 'Up to 7 days': 60, '8-30 days': 40, '31-90 days': 20, 'Over 90 days': 10 }
    for (const [label, count] of Object.entries(want)) {
      const row = (await screen.findByText(label)).parentElement as HTMLElement
      await waitFor(() => expect(within(row).getByText(String(count))).toBeTruthy())
    }
    expect(Object.values(want).reduce((a, b) => a + b, 0)).toBe(130)
  })

  it('past due by severity links to the matching Findings list', async () => {
    renderPage()
    const link = await waitFor(() => {
      const a = screen
        .getAllByText('Critical')
        .map((el) => el.closest('a'))
        .find((el) => el && el.getAttribute('href')?.startsWith('/findings?'))
      expect(a).toBeTruthy()
      return a as HTMLAnchorElement
    })
    expect(drilldownTotal(link.getAttribute('href')!)).toBe(60)
    expect(within(link).getByText('60')).toBeTruthy()
  })

  it('a failed read shows an error and dashes, not zeros', async () => {
    failStats = true
    renderPage()
    expect(await screen.findByText(/Failed to load SLA compliance/)).toBeTruthy()
    const dt = screen.getByText('Past due', { selector: 'dt' })
    expect(within(dt.closest('button') as HTMLElement).queryByText('0')).toBeNull()
  })
})
