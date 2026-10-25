/**
 * Triage mode end to end in the DOM, with the API mocked at its request
 * functions: keys decide and move on, a decision is a conditional write on
 * the shown version, a 412 reloads instead of overwriting, false positive
 * opens the approval request (never a direct write), a finding someone else
 * changed is passed over, keys do nothing in fields, Exit returns to the
 * list, and moving on costs one read.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, configure, fireEvent, render, screen, waitFor } from '@testing-library/react'

// Moving between findings renders the whole page: allow for a loaded runner.
configure({ asyncUtilTimeout: 4000 })
import type { ApiFinding } from '../../../api/finding-api.types'

const routerPush = vi.fn()
const routerBack = vi.fn()
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: routerPush, back: routerBack, replace: vi.fn() }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback?: string, vars?: Record<string, unknown>) =>
      (fallback ?? _k).replace(/\{(\w+)\}/g, (_, v) => String(vars?.[v] ?? '')),
    locale: 'en',
  }),
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlParams: () => new URLSearchParams(window.location.search),
  useUrlSettled: () => true,
}))
const allowed = new Set<string>()
vi.mock('@/lib/permissions', () => ({
  useCanMutate: (k: string) => allowed.has(k),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))
vi.mock('@/features/shared', () => ({
  SeverityBadge: ({ severity }: { severity: string }) => <span>{severity}</span>,
}))
vi.mock('@/features/sla/components/sla-status-badge', () => ({ SlaStatusBadge: () => null }))
vi.mock('../../priority-class-badge', () => ({ PriorityClassBadge: () => null }))
vi.mock('../../exploit-signals', () => ({ ExploitSignals: () => null }))
vi.mock('../../finding-status-badge', () => ({
  FindingStatusBadge: ({ status }: { status: string }) => <span>{status}</span>,
}))
vi.mock('../../detail/finding-evidence-items', () => ({ FindingEvidenceItems: () => null }))
vi.mock('../../../api/use-finding-evidence-items', () => ({
  useFindingEvidenceItems: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('../../../api/use-quick-views', () => ({ refreshFindingQuickViews: vi.fn() }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({ useModuleEnabled: () => true }))
const aiResult: { current: unknown } = { current: undefined }
vi.mock('@/features/ai-triage/api', () => ({
  useTriageResult: () => ({ data: aiResult.current }),
}))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: ({
    onDone,
    onOpenChange,
  }: {
    onDone: () => void
    onOpenChange: (o: boolean) => void
  }) => (
    <div role="dialog" aria-label="add to task">
      <button
        onClick={() => {
          onDone()
          onOpenChange(false)
        }}
      >
        add
      </button>
    </div>
  ),
}))
vi.mock('../../approval-dialog', () => ({
  ApprovalDialog: ({
    targetStatus,
    onSuccess,
    onOpenChange,
    initialJustification,
  }: {
    targetStatus: string
    onSuccess: (r: { single_person?: boolean; id?: string }) => void
    onOpenChange: (o: boolean) => void
    initialJustification?: string
  }) => (
    <div role="dialog" aria-label={`request ${targetStatus}`}>
      <p data-testid="prefill">{initialJustification ?? ''}</p>
      <button
        onClick={() => {
          onOpenChange(false)
          onSuccess({ single_person: false, id: '00000000-0000-4000-8000-0000000000aa' })
        }}
      >
        send request
      </button>
    </div>
  ),
}))
vi.mock('../../assignee-select', () => ({
  AssigneeSelect: ({ onChange }: { onChange: (u: { id: string; name: string }) => void }) => (
    <button onClick={() => onChange({ id: 'u-1', name: 'Ana' })}>assignee picker</button>
  ),
}))

// The finding reads, counted (the request budget).
const findings = new Map<string, ApiFinding>()
const detailReads: string[] = []
const reload = vi.fn()
vi.mock('../../../api/use-findings-api', async () => {
  const React = await import('react')
  return {
    findingDetailKey: (findingId: string) => `/api/v1/findings/${findingId}`,
    useFindingApi: (findingId: string | null) => {
      React.useEffect(() => {
        if (findingId) detailReads.push(findingId)
      }, [findingId])
      return {
        data: findingId ? findings.get(findingId) : undefined,
        error: findingId && !findings.has(findingId) ? notFound() : undefined,
        mutate: reload,
      }
    },
  }
})
function notFound() {
  return Object.assign(new (class extends Error {})('not found'), { statusCode: 404 })
}

const fetchTriageWindow = vi.fn()
const fetchTransitions = vi.fn()
const writeFindingStatus = vi.fn()
const writeFindingAssignee = vi.fn()
const cancelApproval = vi.fn()
const requestRetest = vi.fn()
vi.mock('../../../api/triage-api', () => ({
  fetchFinding: async (fid: string) => findings.get(fid),
  cancelApproval: (...a: unknown[]) => cancelApproval(...a),
  requestRetest: (...a: unknown[]) => requestRetest(...a),
  fetchTriageWindow: (...a: unknown[]) => fetchTriageWindow(...a),
  fetchTransitions: (...a: unknown[]) => fetchTransitions(...a),
  writeFindingStatus: (...a: unknown[]) => writeFindingStatus(...a),
  writeFindingAssignee: (...a: unknown[]) => writeFindingAssignee(...a),
}))

import { TriageMode } from '../triage-mode'
import { ApiClientError } from '@/lib/api/error-handler'

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
function api(n: number, extra: Partial<ApiFinding> = {}): ApiFinding {
  return {
    id: id(n),
    title: `Finding ${n}`,
    status: 'new',
    severity: 'high',
    source: 'dast',
    row_version: 1,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    tool_name: 'nuclei',
    rule_id: `rule-${n}`,
    ...extra,
  } as ApiFinding
}
function seed(count: number) {
  for (let n = 1; n <= count; n++) findings.set(id(n), api(n))
  fetchTriageWindow.mockImplementation(async (_q: string, page: number) => {
    const all = [...findings.values()].filter((f) => f.status === 'new')
    const rows = all.slice((page - 1) * 25, page * 25)
    return {
      items: rows.map((f) => ({ id: f.id, title: f.title, status: f.status, rowVersion: 1 })),
      total: all.length,
      lastPage: page * 25 >= all.length,
    }
  })
}
const press = (key: string, target: Element = document.body) =>
  act(() => {
    fireEvent.keyDown(target, { key })
  })

beforeEach(() => {
  vi.clearAllMocks()
  findings.clear()
  detailReads.length = 0
  sessionStorage.clear()
  allowed.clear()
  for (const k of [
    'PATCH /api/v1/findings/{id}/status',
    'POST /api/v1/findings/{id}/approvals',
    'POST /api/v1/findings/{id}/assign',
    'POST /api/v1/remediation/tasks',
    'POST /api/v1/findings/{id}/retests',
  ])
    allowed.add(k)
  window.history.replaceState(null, '', '/findings/triage?status=new')
  fetchTransitions.mockResolvedValue({
    status: 'new',
    transitions: [
      { to: 'confirmed', allowed: true, mode: 'direct' },
      { to: 'false_positive', allowed: true, mode: 'request' },
      { to: 'accepted', allowed: false, mode: 'request', blocked: [{ code: 'not_allowed_from' }] },
    ],
  })
  writeFindingStatus.mockImplementation(async (fid: string, body: { status: string }) => {
    const f = findings.get(fid)!
    findings.set(fid, { ...f, status: body.status as ApiFinding['status'], row_version: 2 })
    return findings.get(fid)
  })
  writeFindingAssignee.mockResolvedValue({})
  cancelApproval.mockResolvedValue({})
  requestRetest.mockResolvedValue({})
  aiResult.current = undefined
})

afterEach(() => cleanup())

async function ready(title = 'Finding 1') {
  render(<TriageMode />)
  await screen.findByRole('heading', { name: title })
}

describe('TriageMode', () => {
  it('shows the first finding of the queue with its position and a labelled decision region', async () => {
    seed(3)
    await ready()
    expect(fetchTriageWindow).toHaveBeenCalledWith('status=new', 1)
    expect(screen.getByTestId('triage-position')).toHaveTextContent('1 of 3')
    const region = screen.getByRole('region', { name: 'Decision' })
    for (const name of [/Confirm/, /Request false positive/, /Request risk acceptance/, /Skip/]) {
      expect(region.querySelector('button') && screen.getByRole('button', { name })).toBeTruthy()
    }
  })

  it('c confirms with If-Match on the shown version, then moves on by itself', async () => {
    seed(3)
    await ready()
    press('c')
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(writeFindingStatus).toHaveBeenCalledWith(id(1), { status: 'confirmed' }, 1)
    expect(screen.getByTestId('triage-position')).toHaveTextContent('2 of 3')
    expect(screen.getByTestId('triage-counts')).toHaveTextContent('1 decided')
  })

  it('a stale write (412) reloads the finding and stays on it', async () => {
    seed(2)
    writeFindingStatus.mockRejectedValueOnce(new ApiClientError('changed', 'FINDING_CHANGED', 412))
    await ready()
    press('c')
    await waitFor(() => expect(reload).toHaveBeenCalled())
    expect(screen.getByRole('heading', { name: 'Finding 1' })).toBeInTheDocument()
  })

  it('a move the lifecycle blocks is not written', async () => {
    seed(2)
    fetchTransitions.mockResolvedValue({
      status: 'new',
      transitions: [{ to: 'confirmed', allowed: false, blocked: [{ code: 'permission' }] }],
    })
    await ready()
    press('c')
    await waitFor(() => expect(fetchTransitions).toHaveBeenCalled())
    expect(writeFindingStatus).not.toHaveBeenCalled()
  })

  it('f opens the false positive request (never a status write) and the request moves on', async () => {
    seed(2)
    await ready()
    press('f')
    const dialog = await screen.findByRole('dialog', { name: 'request false_positive' })
    // Keys do nothing while the dialog is open.
    press('c', dialog)
    press('s')
    expect(writeFindingStatus).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'send request' }))
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(screen.getByTestId('triage-counts')).toHaveTextContent('1 sent for approval')
  })

  it('a acceptance the lifecycle does not allow from new opens no dialog', async () => {
    seed(2)
    await ready()
    press('a')
    await waitFor(() => expect(fetchTransitions).toHaveBeenCalledWith(id(1)))
    const { toast } = await import('sonner')
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('heading', { name: 'Finding 1' })).toBeInTheDocument()
  })

  it('without the status permission, c does nothing and the button is disabled', async () => {
    seed(2)
    allowed.delete('PATCH /api/v1/findings/{id}/status')
    await ready()
    expect(screen.getByRole('button', { name: /^Confirm/ })).toBeDisabled()
    press('c')
    expect(fetchTransitions).not.toHaveBeenCalled()
  })

  it('a pentest finding cannot be decided here', async () => {
    seed(1)
    findings.set(id(1), api(1, { source: 'pentest' }))
    await ready()
    expect(screen.getByRole('note')).toHaveTextContent(/own workflow/)
    press('c')
    press('f')
    expect(fetchTransitions).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('o assigns through the picker and moves on', async () => {
    seed(2)
    await ready()
    press('o')
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(writeFindingAssignee).toHaveBeenCalledWith(id(1), 'u-1', 1)
  })

  it('j / k move without deciding; s skips', async () => {
    seed(3)
    await ready()
    press('j')
    await screen.findByRole('heading', { name: 'Finding 2' })
    press('k')
    await screen.findByRole('heading', { name: 'Finding 1' })
    press('s')
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(screen.getByTestId('triage-counts')).toHaveTextContent('1 skipped')
  })

  it('keys typed into a field are not decisions', async () => {
    seed(2)
    await ready()
    const input = document.createElement('input')
    document.body.appendChild(input)
    press('c', input)
    press('s', input)
    expect(fetchTransitions).not.toHaveBeenCalled()
    expect(screen.getByRole('heading', { name: 'Finding 1' })).toBeInTheDocument()
    input.remove()
  })

  it('passes over a finding someone else changed, with a note', async () => {
    seed(3)
    findings.set(id(2), api(2, { status: 'confirmed', row_version: 4 }))
    // The window was read before the change: it still lists finding 2 as new.
    fetchTriageWindow.mockResolvedValueOnce({
      items: [1, 2, 3].map((n) => ({
        id: id(n),
        title: `Finding ${n}`,
        status: 'new',
        rowVersion: 1,
      })),
      total: 3,
      lastPage: true,
    })
    await ready()
    press('s')
    await screen.findByRole('heading', { name: 'Finding 3' })
    const { toast } = await import('sonner')
    expect(toast.info).toHaveBeenCalledWith(expect.stringMatching(/Changed by someone else/))
  })

  it('moving on costs one read per finding', async () => {
    seed(6)
    await ready()
    for (let i = 0; i < 5; i++) press('j')
    await screen.findByRole('heading', { name: 'Finding 6' })
    expect(detailReads).toEqual([1, 2, 3, 4, 5, 6].map(id))
    expect(fetchTriageWindow).toHaveBeenCalledTimes(1)
  })

  it('reaching the end shows the queue is done', async () => {
    seed(1)
    await ready()
    press('c')
    expect(await screen.findByTestId('triage-done')).toHaveTextContent('Queue done')
  })

  it('Esc returns to the list it came from', async () => {
    seed(1)
    sessionStorage.setItem(
      'openctem.findings.triage',
      JSON.stringify({
        v: 1,
        query: 'status=new',
        returnTo: '/findings?severity=critical',
        fromList: false,
        viewKey: 'needs_triage',
        items: [],
        index: 0,
        outcomes: {},
        total: 0,
        exhausted: false,
      })
    )
    await ready()
    // The queue is named after the view it was started from.
    expect(screen.getByTestId('triage-top-bar')).toHaveTextContent('Needs triage')
    press('Escape')
    expect(routerPush).toHaveBeenCalledWith('/findings?severity=critical')
    expect(sessionStorage.getItem('openctem.findings.triage')).toBeNull()
  })

  it('a reload resumes the session where it was', async () => {
    seed(3)
    const { unmount } = render(<TriageMode />)
    await screen.findByRole('heading', { name: 'Finding 1' })
    press('s')
    await screen.findByRole('heading', { name: 'Finding 2' })
    unmount()
    render(<TriageMode />)
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(fetchTriageWindow).toHaveBeenCalledTimes(1)
  })
})

describe('TriageMode decisions, part 2', () => {
  it('m adds to a task and moves on', async () => {
    seed(2)
    await ready()
    press('m')
    fireEvent.click(await screen.findByRole('button', { name: 'add' }))
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(screen.getByTestId('triage-counts')).toHaveTextContent('1 decided')
  })

  it('r requests a retest and moves on; without findings:verify it does nothing', async () => {
    seed(3)
    await ready()
    press('r')
    await screen.findByRole('heading', { name: 'Finding 2' })
    expect(requestRetest).toHaveBeenCalledWith(id(1))
    allowed.delete('POST /api/v1/findings/{id}/retests')
    cleanup()
    sessionStorage.clear()
    await ready()
    press('r')
    expect(requestRetest).toHaveBeenCalledTimes(1)
  })

  it('u cancels a sent request (never deletes it) and shows the finding again', async () => {
    seed(2)
    await ready()
    press('f')
    fireEvent.click(await screen.findByRole('button', { name: 'send request' }))
    await screen.findByRole('heading', { name: 'Finding 2' })
    press('u')
    await screen.findByRole('heading', { name: 'Finding 1' })
    expect(cancelApproval).toHaveBeenCalledWith('00000000-0000-4000-8000-0000000000aa')
    expect(screen.getByTestId('triage-counts')).toHaveTextContent('0 sent for approval')
  })

  it('u gives an assignment back to the previous assignee on the current version', async () => {
    seed(2)
    await ready()
    press('o')
    await screen.findByRole('heading', { name: 'Finding 2' })
    findings.set(id(1), { ...findings.get(id(1))!, row_version: 7 })
    press('u')
    await screen.findByRole('heading', { name: 'Finding 1' })
    expect(writeFindingAssignee).toHaveBeenLastCalledWith(id(1), null, 7)
  })

  it('u on a confirm the lifecycle cannot reverse says so and writes nothing', async () => {
    seed(2)
    await ready()
    press('c')
    await screen.findByRole('heading', { name: 'Finding 2' })
    writeFindingStatus.mockClear()
    press('u')
    const { toast } = await import('sonner')
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
    expect(writeFindingStatus).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.getByRole('button', { name: /^Undo last/ })).toBeDisabled())
  })

  it('u keeps at most ten decisions', async () => {
    seed(12)
    await ready()
    for (let i = 1; i <= 11; i++) {
      press('s')
      await screen.findByRole('heading', { name: `Finding ${i + 1}` })
    }
    expect(screen.getByRole('button', { name: /^Undo last/ })).toHaveTextContent('10 to undo')
  })

  it('Exit after decisions shows the receipt first', async () => {
    seed(2)
    await ready()
    press('c')
    await screen.findByRole('heading', { name: 'Finding 2' })
    press('Escape')
    expect(await screen.findByTestId('triage-receipt')).toHaveTextContent('Finding 1')
    expect(routerPush).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Back to the list' }))
    expect(routerPush).toHaveBeenCalledWith('/findings')
  })

  it('the AI suggestion only fills the request form', async () => {
    seed(2)
    aiResult.current = {
      status: 'completed',
      summary: 'Probably a test fixture.',
      falsePositiveLikelihood: 0.9,
      falsePositiveReason: 'Test host only.',
    }
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Apply suggestion' }))
    await screen.findByRole('dialog', { name: 'request false_positive' })
    expect(screen.getByTestId('prefill')).toHaveTextContent('Test host only.')
    expect(writeFindingStatus).not.toHaveBeenCalled()
  })
})
