/**
 * useFindingTriage — a write is conditional on the finding version shown.
 *
 * Each write sends the row_version the person decided on (If-Match). When
 * someone else changed the finding meanwhile the API answers 409
 * FINDING_CHANGED: the triage reverts its optimistic state, reloads the
 * finding and says so, instead of a generic error.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, render, act, fireEvent, waitFor } from '@testing-library/react'

import { ApiClientError } from '@/lib/api/error-handler'
import { useFindingTriage, type FindingTriageTarget } from '../use-finding-triage'

const updateStatus = vi.fn()
const updateSeverity = vi.fn()
const invalidate = vi.fn()
vi.mock('swr', () => ({ mutate: vi.fn() }))
vi.mock('../../api/use-findings-api', () => ({
  invalidateFindingsCache: () => invalidate(),
  findingDetailKey: (id: string) => `/api/v1/findings/${id}`,
  useUpdateFindingStatusApi: () => ({ trigger: updateStatus, isMutating: false }),
  useUpdateFindingSeverityApi: () => ({ trigger: updateSeverity, isMutating: false }),
  useAssignFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUnassignFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('../../components/approval-dialog', () => ({ ApprovalDialog: () => null }))
vi.mock('../../api/use-finding-lifecycles', () => ({
  useSubStatusCatalog: () => new Map(),
  subStatusName: (s: { name: string }) => s.name,
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const target = (over: Partial<FindingTriageTarget> = {}): FindingTriageTarget => ({
  id: 'f1',
  status: 'in_progress',
  severity: 'high',
  rowVersion: 7,
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  updateSeverity.mockReset()
})

// A severity change asks for its reason first: pick the severity, answer the
// reason dialog and confirm.
async function changeSeverityWithReason(
  result: { current: ReturnType<typeof useFindingTriage> },
  to: 'critical' | 'low'
) {
  const toasts = () =>
    toast.success.mock.calls.length + toast.info.mock.calls.length + toast.error.mock.calls.length
  const before = toasts()
  act(() => result.current.changeSeverity(to))
  const { getByLabelText, getByRole, unmount } = render(<>{result.current.dialogs}</>)
  fireEvent.change(getByLabelText(/Reason/), { target: { value: 'because of the evidence' } })
  await act(async () => {
    fireEvent.click(getByRole('button', { name: 'Change severity' }))
  })
  // The write settles through several awaits; wait for its toast.
  await waitFor(() => expect(toasts()).toBeGreaterThan(before))
  unmount()
}

describe('useFindingTriage — optimistic concurrency', () => {
  it('sends the version shown, then the version the write returned', async () => {
    updateSeverity
      .mockResolvedValueOnce({ row_version: 8 })
      .mockResolvedValueOnce({ row_version: 9 })
    const { result } = renderHook(() => useFindingTriage(target()))

    await changeSeverityWithReason(result, 'critical')
    expect(updateSeverity).toHaveBeenLastCalledWith({
      severity: 'critical',
      reason: 'because of the evidence',
      rowVersion: 7,
    })

    await changeSeverityWithReason(result, 'low')
    expect(updateSeverity).toHaveBeenLastCalledWith({
      severity: 'low',
      reason: 'because of the evidence',
      rowVersion: 8,
    })
  })

  it('on FINDING_CHANGED keeps the severity, reloads the finding and says so', async () => {
    updateSeverity.mockRejectedValueOnce(
      new ApiClientError('changed', 'FINDING_CHANGED', 409, { row_version: 9 })
    )
    const { result } = renderHook(() => useFindingTriage(target()))

    await changeSeverityWithReason(result, 'critical')
    expect(result.current.severity).toBe('high')
    expect(invalidate).toHaveBeenCalled()
    expect(toast.info).toHaveBeenCalledTimes(1)
    expect(toast.error).not.toHaveBeenCalled()
  })

  it('keeps the generic error for any other failure', async () => {
    updateSeverity.mockRejectedValueOnce(new ApiClientError('boom', 'INTERNAL_ERROR', 500))
    const { result } = renderHook(() => useFindingTriage(target()))

    await changeSeverityWithReason(result, 'critical')
    expect(toast.error).toHaveBeenCalledTimes(1)
    expect(toast.info).not.toHaveBeenCalled()
  })
})
