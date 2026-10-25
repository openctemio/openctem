/**
 * My Work: persona tabs whose counts are the totals of the lists they open,
 * a review queue decided in place, next steps on an empty queue, and entry
 * to triage mode. The API is mocked at the hooks; the API side is covered by
 * finding_approval_queue_db_test.go and findings_quick_views_db_test.go.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import en from '@/lib/i18n/dictionaries/en/myWork.json'
import enFindings from '@/lib/i18n/dictionaries/en/findings.json'
import viDict from '@/lib/i18n/dictionaries/vi/myWork.json'

const search = { value: '' }
const replace = vi.fn()
const push = vi.fn()
const perms = new Set<string>()
let locale = 'en'

const VIEWS = [
  { key: 'needs_triage', count: 9, params: 'status=new&informational=false' },
  { key: 'my_queue', count: 7, params: 'state=open&related_to=me&informational=false' },
  { key: 'accepted_expiring', count: 3, params: 'status=accepted&acceptance_expires_at_lte=P30D' },
  { key: 'my_team', count: 23, params: 'state=open&related_to=my_team&informational=false' },
  {
    key: 'my_due_soon',
    count: 4,
    params: 'state=open&related_to=me&sla_deadline_lte=P3D&informational=false',
  },
  {
    key: 'my_accepted_expiring',
    count: 1,
    params: 'status=accepted&acceptance_expires_at_lte=P30D&related_to=me',
  },
]
const quickViews = { data: { views: VIEWS, include_informational: false } as unknown }
const findingQueue = vi.fn((_params?: string, _sort?: string, _enabled?: boolean) => ({
  data: { data: [] as unknown[], total: 0 },
  error: undefined,
  isLoading: false,
  mutate: vi.fn(),
}))
let approvalRows: unknown[] = []
const approvalQueue = vi.fn((_queue: string, _perPage: number) => ({
  data: {
    data: approvalRows,
    total: approvalRows.length,
    queue_counts: { review: approvalRows.length, requested: 2 },
  },
  error: undefined,
  isLoading: false,
  mutate: vi.fn(),
}))
const startSession = vi.fn()
const approveTrigger = vi.fn()
const rejectTrigger = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace }),
  useSearchParams: () => new URLSearchParams(search.value),
  usePathname: () => '/my-work',
}))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    locale,
    t: (k: string, fb?: string, vars?: Record<string, string | number>) => {
      const dict = {
        ...(enFindings as Record<string, string>),
        ...((locale === 'vi' ? viDict : en) as Record<string, string>),
      }
      let s = dict[k] ?? (typeof fb === 'string' ? fb : k)
      for (const [n, v] of Object.entries(vars ?? {})) s = s.replace(`{${n}}`, String(v))
      return s
    },
  }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.has(p) }),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't' } }) }))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'me' }) }))
vi.mock('@/hooks/use-dynamic-badges', () => ({ refreshPendingApprovalCount: vi.fn() }))
vi.mock('@/features/findings/api/use-quick-views', () => ({
  useFindingQuickViews: () => ({
    ...quickViews,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('@/features/my-work/api/use-my-work', () => ({
  useFindingQueue: (p?: string, s?: string, e?: boolean) => findingQueue(p, s, e),
  useApprovalQueue: (q: string, n: number) => approvalQueue(q, n),
}))
vi.mock('@/features/findings/lib/triage-session', async (orig) => ({
  ...(await orig<object>()),
  startSession: (...a: unknown[]) => startSession(...a),
}))
vi.mock('@/features/findings/api/use-findings-api', async (orig) => ({
  ...(await orig<object>()),
  useApproveStatus: () => ({ trigger: approveTrigger, isMutating: false }),
  useRejectApproval: () => ({ trigger: rejectTrigger, isMutating: false }),
}))
vi.mock('@/features/remediation-hub/components/my-tasks-queue', () => ({
  MyTasksQueue: () => <p>tasks queue</p>,
  useMyTaskCount: (enabled: boolean) => (enabled ? 5 : undefined),
}))
vi.mock('@/features/findings/components/priority-class-badge', () => ({
  PriorityClassBadge: ({ priorityClass }: { priorityClass: string }) => (
    <span>{priorityClass}</span>
  ),
}))
vi.mock('@/features/findings/components/approval-finding-summary', () => ({
  ApprovalFindingSummary: ({ findingTitle }: { findingTitle?: string }) => <p>{findingTitle}</p>,
}))

import { MyWorkPage } from '../components/my-work-page'

const renderPage = () =>
  render(
    <TooltipProvider>
      <MyWorkPage />
    </TooltipProvider>
  )

const request = (over: Record<string, unknown> = {}) => ({
  id: 'r1',
  tenant_id: 't',
  finding_id: 'f1',
  finding_title: 'Remote code execution in edge proxy',
  requested_status: 'accepted',
  requested_by: 'u2',
  requested_by_name: 'Linh',
  justification: 'WAF rule blocks the path',
  status: 'pending',
  created_at: '2026-10-25T08:00:00Z',
  expires_at: '2027-01-23T08:00:00Z',
  approvals_required: 1,
  approvals_collected: 0,
  finding: { severity: 'critical', kev: true, epss: 0.42, asset_name: 'edge-proxy' },
  changed_since_request: ['kev'],
  ...over,
})

describe('My Work page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    search.value = ''
    locale = 'en'
    approvalRows = []
    perms.clear()
    perms.add('findings:approve')
    perms.add('findings:remediation:read')
    perms.add('findings:status')
  })

  it('shows the persona tabs with the counts of the lists they open', () => {
    renderPage()
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent)
    expect(tabs).toEqual([
      'Assigned to me7',
      'My team23',
      'Awaiting my review0',
      'Requested by me2',
      'Acceptances expiring1',
      'My tasks5',
    ])
    // Assigned to me lists the my_queue view's own params, nearest SLA first.
    const [params, sort, enabled] = findingQueue.mock.calls.at(-1)!
    expect(params).toBe('state=open&related_to=me&informational=false')
    expect(sort).toMatch(/^sla_deadline/)
    expect(enabled).toBe(true)
  })

  it('leaves out Awaiting my review without findings:approve and My tasks without remediation read', () => {
    perms.delete('findings:approve')
    perms.delete('findings:remediation:read')
    search.value = 'tab=review'
    renderPage()
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent ?? '')
    expect(tabs.some((t) => t.startsWith('Awaiting my review'))).toBe(false)
    expect(tabs.some((t) => t.startsWith('My tasks'))).toBe(false)
    // The URL's tab is not theirs: the first tab opens instead.
    expect(screen.getByRole('tab', { name: /Assigned to me/ })).toHaveAttribute(
      'aria-selected',
      'true'
    )
    // Only the requested queue is asked for (its counts).
    expect(approvalQueue.mock.calls.every(([q]) => q === 'requested')).toBe(true)
  })

  it('narrows Assigned to me to findings due in 72 hours with the quick chip', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /SLA due in 72 hours\s*4/ }))
    expect(replace).toHaveBeenCalledWith('/my-work?due=72h', { scroll: false })

    search.value = 'due=72h'
    renderPage()
    const [params] = findingQueue.mock.calls.at(-1)!
    expect(params).toBe('state=open&related_to=me&sla_deadline_lte=P3D&informational=false')
  })

  it('opens My team with its own view and links View all to the same list', () => {
    search.value = 'tab=team'
    findingQueue.mockReturnValue({
      data: {
        data: [{ id: 'f9', title: 'Outdated OpenSSL', severity: 'high', status: 'confirmed' }],
        total: 23,
      },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    })
    renderPage()
    expect(findingQueue.mock.calls.at(-1)![0]).toBe(
      'state=open&related_to=my_team&informational=false'
    )
    expect(screen.getByRole('link', { name: /View all/ })).toHaveAttribute(
      'href',
      '/findings?state=open&related_to=my_team'
    )
    expect(screen.getByText('Top 1 of 23')).toBeInTheDocument()
  })

  it('lists requests awaiting my review with what changed, decided in place', async () => {
    search.value = 'tab=review'
    approvalRows = [request()]
    renderPage()
    expect(approvalQueue).toHaveBeenCalledWith('review', 25)
    const row = screen.getByRole('listitem', { name: /Risk acceptance: Remote code execution/ })
    expect(within(row).getByText('Changed since the request: now in CISA KEV')).toBeInTheDocument()
    expect(within(row).getByText('90 days')).toBeInTheDocument()
    expect(within(row).getByText('edge-proxy')).toBeInTheDocument()
    expect(within(row).getByText('Requested by Linh')).toBeInTheDocument()
    expect(screen.getByText(/Four-eyes/)).toBeInTheDocument()

    fireEvent.click(within(row).getByRole('button', { name: /Approve/ }))
    const dialog = await screen.findByRole('alertdialog')
    approveTrigger.mockResolvedValue({ status: 'approved' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }))
    await vi.waitFor(() => expect(approveTrigger).toHaveBeenCalledTimes(1))
  })

  it('never offers a decision on my own request', () => {
    search.value = 'tab=review'
    approvalRows = [request({ requested_by: 'me' })]
    renderPage()
    const row = screen.getByRole('listitem')
    expect(within(row).queryByRole('button', { name: /Approve/ })).toBeNull()
    expect(within(row).getByText('Your request: another person decides')).toBeInTheDocument()
  })

  it('moves with j and k and rejects with r, asking for a reason', async () => {
    search.value = 'tab=review'
    approvalRows = [
      request(),
      request({ id: 'r2', finding_id: 'f2', finding_title: 'Path traversal' }),
    ]
    renderPage()
    const rows = screen.getAllByRole('listitem')
    rows[0].focus()
    fireEvent.keyDown(rows[0], { key: 'j' })
    expect(document.activeElement).toBe(rows[1])
    fireEvent.keyDown(rows[1], { key: 'r' })
    const dialog = await screen.findByRole('dialog')
    const reject = within(dialog).getByRole('button', { name: 'Reject' })
    expect(reject).toBeDisabled()
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: 'needs a fix date' } })
    rejectTrigger.mockResolvedValue({})
    fireEvent.click(reject)
    await vi.waitFor(() =>
      expect(rejectTrigger).toHaveBeenCalledWith({ reason: 'needs a fix date' })
    )
  })

  it('offers the next step on an empty review queue', () => {
    search.value = 'tab=review'
    renderPage()
    expect(screen.getByText('Nothing waits on you')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next: review 4 findings due in 72 hours' }))
    expect(replace).toHaveBeenCalledWith('/my-work?due=72h', { scroll: false })
  })

  it('enters triage mode on the Needs triage view', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /^Triage\s*9$/ }))
    expect(startSession).toHaveBeenCalledWith(
      'status=new&informational=false',
      '/findings?status=new&state=all',
      'needs_triage'
    )
    expect(push).toHaveBeenCalledWith(expect.stringMatching(/^\/findings\/triage\?status=new/))
  })

  it('hides triage without findings:status', () => {
    perms.delete('findings:status')
    renderPage()
    expect(screen.queryByRole('button', { name: /^Triage/ })).toBeNull()
  })

  it('reads in Vietnamese', () => {
    locale = 'vi'
    renderPage()
    expect(screen.getByRole('heading', { name: 'Việc của tôi' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Chờ tôi duyệt/ })).toBeInTheDocument()
  })
})
