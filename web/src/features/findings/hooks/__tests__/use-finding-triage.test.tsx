/**
 * useFindingTriage — the "follow the server" effects must not loop.
 *
 * The parent (findings detail page / drawer) rebuilds the `finding` object — and
 * a fresh `assignee` object — on every render. Keying the sync effects on the
 * assignee OBJECT, or calling setState unconditionally with a new reference,
 * re-fires the effect every render and the page throws "Maximum update depth
 * exceeded". These tests pin the primitive-keyed, idempotent behaviour.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, render, act, fireEvent } from '@testing-library/react'

import { useFindingTriage, type FindingTriageTarget } from '../use-finding-triage'
import type { FindingUser } from '../../types'

// The API mutation hooks: never actually called in these tests, but the hook
// wires them up on mount.
const updateStatus = vi.fn()
const updateSeverity = vi.fn()
const swrMutate = vi.fn()
vi.mock('swr', () => ({ mutate: (...args: unknown[]) => swrMutate(...args) }))
vi.mock('../../api/use-findings-api', () => ({
  invalidateFindingsCache: vi.fn(),
  findingDetailKey: (id: string) => `/api/v1/findings/${id}`,
  useUpdateFindingStatusApi: () => ({ trigger: updateStatus, isMutating: false }),
  useUpdateFindingSeverityApi: () => ({ trigger: updateSeverity, isMutating: false }),
  useAssignFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUnassignFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
}))

vi.mock('../../components/approval-dialog', () => ({
  ApprovalDialog: () => null,
}))

vi.mock('../../api/use-finding-lifecycles', () => ({
  useSubStatusCatalog: () => new Map(),
  subStatusName: (s: { name: string }) => s.name,
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

const user = (id: string, name = id): FindingUser => ({
  id,
  name,
  email: `${id}@example.test`,
  role: 'member' as FindingUser['role'],
})

const target = (over: Partial<FindingTriageTarget> = {}): FindingTriageTarget => ({
  id: 'f1',
  status: 'new',
  severity: 'high',
  ...over,
})

beforeEach(() => vi.clearAllMocks())

describe('useFindingTriage — no render loop', () => {
  it('keeps the assignee stable when the parent passes a NEW object with the same id', () => {
    const { result, rerender } = renderHook(({ f }) => useFindingTriage(f), {
      initialProps: { f: target({ assignee: user('u1', 'Alice') }) },
    })

    const first = result.current.assignee
    expect(first?.id).toBe('u1')

    // The parent re-renders with a brand-new assignee object (same person). The
    // effect must NOT adopt the new reference — that would be a new state value
    // every render and loop.
    rerender({ f: target({ assignee: user('u1', 'Alice') }) })
    expect(result.current.assignee).toBe(first)

    rerender({ f: target({ assignee: user('u1', 'Alice') }) })
    expect(result.current.assignee).toBe(first)
  })

  it('follows the server when the assignee actually changes', () => {
    const { result, rerender } = renderHook(({ f }) => useFindingTriage(f), {
      initialProps: { f: target({ assignee: user('u1') }) },
    })
    expect(result.current.assignee?.id).toBe('u1')

    rerender({ f: target({ assignee: user('u2') }) })
    expect(result.current.assignee?.id).toBe('u2')

    rerender({ f: target({ assignee: undefined }) })
    expect(result.current.assignee).toBeUndefined()
  })

  it('follows the server on status and severity, idempotently', () => {
    const { result, rerender } = renderHook(({ f }) => useFindingTriage(f), {
      initialProps: { f: target({ status: 'new', severity: 'high' }) },
    })
    expect(result.current.status).toBe('new')
    expect(result.current.severity).toBe('high')

    rerender({ f: target({ status: 'confirmed', severity: 'critical' }) })
    expect(result.current.status).toBe('confirmed')
    expect(result.current.severity).toBe('critical')
  })

  // The real-world reproduction: a parent that rebuilds the finding (and its
  // assignee object) on every single render. Before the fix this re-fired the
  // assignee effect each render, which setState'd a new reference, which
  // re-rendered — an unbounded loop that React aborts with "Maximum update depth
  // exceeded". With the fix the component settles to a small, bounded number of
  // renders.
  it('settles (bounded render count) when the parent recreates the finding every render', () => {
    let renders = 0
    function Harness() {
      renders += 1
      // Fresh objects every render — exactly what toFindingDetail(apiFinding) does.
      const finding = target({ assignee: user('u1', 'Alice') })
      useFindingTriage(finding)
      return null
    }

    expect(() => render(<Harness />)).not.toThrow()
    // A loop would blow past React's ~50 update-depth limit. A handful (mount +
    // StrictMode double-invoke + one settling pass) is expected.
    expect(renders).toBeLessThan(10)
  })
})

describe('useFindingTriage — notes', () => {
  it('asks for a note before a fix claim, sending nothing until then', async () => {
    const { result } = renderHook(() => useFindingTriage(target({ status: 'in_progress' })))
    act(() => result.current.changeStatus('fix_applied'))
    // The note dialog is shown; nothing is sent and the status is unchanged.
    expect(result.current.status).toBe('in_progress')
    render(<>{result.current.dialogs}</>)
    expect(document.querySelector('#status-note')).not.toBeNull()
  })
})

describe('useFindingTriage — Undo', () => {
  it('offers Undo on a non-closing move, never on a resolve', async () => {
    const { toast } = await import('sonner')
    const { result } = renderHook(() => useFindingTriage(target({ status: 'confirmed' })))
    await act(async () => {
      await result.current.changeStatus('in_progress')
    })
    const opened = vi.mocked(toast.success).mock.calls.at(-1)?.[1] as { action?: unknown }
    expect(opened?.action).toBeTruthy()

    // A resolve asks for its note first; confirm it.
    act(() => result.current.changeStatus('resolved'))
    const { getByLabelText, getByRole } = render(<>{result.current.dialogs}</>)
    fireEvent.change(getByLabelText('Note (required)'), { target: { value: 'patched' } })
    await act(async () => {
      fireEvent.click(getByRole('button', { name: 'Save' }))
    })
    const resolved = vi.mocked(toast.success).mock.calls.at(-1)?.[1] as { action?: unknown }
    expect(resolved?.action).toBeUndefined()
  })
})

describe('useFindingTriage — organization lifecycle moves', () => {
  function Harness({ f }: { f: FindingTriageTarget }) {
    const triage = useFindingTriage(f)
    return (
      <>
        <button
          onClick={() =>
            triage.changeStatus('in_progress', {
              to: 'in_progress',
              allowed: true,
              mode: 'direct',
              to_sub_status_id: 'sub-review',
              name: 'Send to review',
              note_min_len: 5,
              fields: ['ticket_link'],
            })
          }
        >
          move
        </button>
        <button
          onClick={() =>
            triage.changeStatus('in_progress', {
              to: 'in_progress',
              allowed: true,
              mode: 'direct',
              to_sub_status_id: 'sub-wait',
            })
          }
        >
          relabel
        </button>
        <span data-testid="sub">{triage.subStatusId ?? ''}</span>
        {triage.dialogs}
      </>
    )
  }

  it('asks for the required fields and note, then sends them with the sub-status', async () => {
    updateStatus.mockResolvedValue({ sub_status_id: 'sub-review' })
    const view = render(<Harness f={target({ status: 'confirmed' })} />)
    fireEvent.click(view.getByText('move'))
    expect(updateStatus).not.toHaveBeenCalled()
    const confirm = view.getByRole('button', { name: /^move$/i })
    expect(confirm).toBeDisabled()
    fireEvent.change(view.getByLabelText(/ticket link/i), {
      target: { value: 'https://tickets.example.com/SEC-1' },
    })
    fireEvent.change(view.getByLabelText(/note/i), { target: { value: 'too' } })
    expect(confirm).toBeDisabled()
    fireEvent.change(view.getByLabelText(/note/i), { target: { value: 'long enough' } })
    await act(async () => {
      fireEvent.click(confirm)
    })
    expect(updateStatus).toHaveBeenCalledWith({
      status: 'in_progress',
      resolution: 'long enough',
      sub_status_id: 'sub-review',
      fields: { ticket_link: 'https://tickets.example.com/SEC-1' },
    })
    expect(view.getByTestId('sub')).toHaveTextContent('sub-review')
  })

  it('relabels inside the current status without a dialog', async () => {
    updateStatus.mockResolvedValue({ sub_status_id: 'sub-wait' })
    const view = render(<Harness f={target({ status: 'in_progress' })} />)
    await act(async () => {
      fireEvent.click(view.getByText('relabel'))
    })
    expect(updateStatus).toHaveBeenCalledWith({
      status: 'in_progress',
      resolution: undefined,
      sub_status_id: 'sub-wait',
    })
  })
})

describe('useFindingTriage — severity', () => {
  it('asks for a reason first, then writes the recomputed priority and SLA into the cache', async () => {
    updateSeverity.mockResolvedValue({
      id: 'f1',
      severity: 'critical',
      source_severity: 'high',
      severity_override: { reason: 'exploited', overridden_at: '2026-10-18T00:00:00Z' },
      priority_class: 'P1',
      priority_class_reason: 'Critical severity, reachable',
      sla_deadline: '2026-10-25T00:00:00Z',
      sla_status: 'on_track',
    })
    const { result } = renderHook(() => useFindingTriage(target({ severity: 'high' })))
    act(() => result.current.changeSeverity('critical'))
    // Nothing is sent before the reason.
    expect(updateSeverity).not.toHaveBeenCalled()
    const { getByLabelText, getByRole } = render(<>{result.current.dialogs}</>)
    fireEvent.change(getByLabelText(/Reason/), { target: { value: 'exploited' } })
    await act(async () => {
      fireEvent.click(getByRole('button', { name: 'Change severity' }))
    })
    expect(updateSeverity).toHaveBeenCalledWith({ severity: 'critical', reason: 'exploited' })
    expect(result.current.severity).toBe('critical')
    // The cached finding takes the answer's priority, reason and deadline.
    const [key, update] = swrMutate.mock.calls[0] as [string, (cur: object) => object]
    expect(key).toBe('/api/v1/findings/f1')
    expect(update({ id: 'f1', priority_class: 'P2', title: 'kept' })).toMatchObject({
      title: 'kept',
      priority_class: 'P1',
      priority_class_reason: 'Critical severity, reachable',
      sla_deadline: '2026-10-25T00:00:00Z',
      source_severity: 'high',
    })
  })

  it('keeps the severity when the downgrade waits for approval', async () => {
    const { toast } = await import('sonner')
    updateSeverity.mockResolvedValue({
      id: 'f1',
      severity: 'high',
      pending_severity_request: { id: 'r1', requested_severity: 'low' },
    })
    const { result } = renderHook(() => useFindingTriage(target({ severity: 'high' })))
    act(() => result.current.changeSeverity('low'))
    const { getByLabelText, getByRole } = render(<>{result.current.dialogs}</>)
    fireEvent.change(getByLabelText(/Reason/), { target: { value: 'test host only' } })
    await act(async () => {
      fireEvent.click(getByRole('button', { name: 'Change severity' }))
    })
    expect(result.current.severity).toBe('high')
    expect(toast.info).toHaveBeenCalled()
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('restores the source severity with a reason', async () => {
    updateSeverity.mockResolvedValue({ id: 'f1', severity: 'medium' })
    const { result } = renderHook(() =>
      useFindingTriage(target({ severity: 'high', sourceSeverity: 'medium' }))
    )
    act(() => result.current.restoreSeverity())
    const { getByLabelText, getByRole } = render(<>{result.current.dialogs}</>)
    fireEvent.change(getByLabelText(/Reason/), { target: { value: 'scanner was right' } })
    await act(async () => {
      fireEvent.click(getByRole('button', { name: 'Restore' }))
    })
    expect(updateSeverity).toHaveBeenCalledWith({ restore: true, reason: 'scanner was right' })
    expect(result.current.severity).toBe('medium')
  })
})
