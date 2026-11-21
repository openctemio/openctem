/**
 * The bulk Dismiss dialog: the server's preview in plain words, the note
 * required or optional as the preview says (D4), a selection above 500
 * offering a suppression rule, a changed list asking again, the keyboard,
 * one idempotency key per request, and Undo from the result toast.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiClientError } from '@/lib/api/error-handler'
import { BulkDismissDialog } from '../bulk-dismiss-dialog'
import { announceDismissResult } from '../bulk-dismiss-result'
import type { DismissResult } from '../../lib/bulk-dismiss'

const post = vi.fn()
vi.mock('@/lib/api/client', () => ({
  post: (...args: unknown[]) => post(...args),
}))

const toastFns = vi.hoisted(() => ({
  success: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: toastFns }))

function preview(over: Partial<DismissResult> = {}): DismissResult {
  return {
    status: 'preview',
    decided: [],
    grouped: null,
    skipped: [],
    counts: { decided: 38, grouped: 4, skipped: 2, budget_overflow: 0 },
    step_up_required: false,
    note_required: true,
    note_min_length: 1,
    replay: false,
    decided_now: [{ id: 'f1', title: 'Outdated TLS on example.com', severity: 'low' }],
    to_approval: [{ id: 'f2', title: 'SQL injection in login', severity: 'high' }],
    skipped_items: [
      { id: 'f3', reason: 'pending_request' },
      { id: 'f4', reason: 'pending_request' },
    ],
    ...over,
  }
}

const IDS = { kind: 'ids' as const, ids: ['f1', 'f2', 'f3'] }

function renderDialog(props: Partial<React.ComponentProps<typeof BulkDismissDialog>> = {}) {
  const onApplied = vi.fn()
  const onOpenChange = vi.fn()
  const onCreateRule = vi.fn()
  render(
    <BulkDismissDialog
      open
      onOpenChange={onOpenChange}
      selection={IDS}
      onApplied={onApplied}
      onCreateRule={onCreateRule}
      {...props}
    />
  )
  return { onApplied, onOpenChange, onCreateRule }
}

/** Calls to one endpoint. */
const callsTo = (path: string) => post.mock.calls.filter(([p]) => p === path)

beforeEach(() => {
  post.mockReset()
  window.localStorage.clear()
  Object.values(toastFns).forEach((f) => f.mockReset())
})
afterEach(() => vi.useRealTimers())

describe('BulkDismissDialog', () => {
  it('shows the server preview in plain words, each part expandable', async () => {
    post.mockResolvedValue(preview())
    renderDialog()
    const panel = await screen.findByTestId('bulk-dismiss-preview')
    expect(await within(panel).findByText('38 will be dismissed now.')).toBeInTheDocument()
    expect(
      within(panel).getByText('4 need a second person: they go to approval (one request).')
    ).toBeInTheDocument()
    expect(within(panel).getByText('2 skipped: already waiting for approval.')).toBeInTheDocument()
    // The preview asked with the ids and a reason, changing nothing.
    const [path, body] = post.mock.calls[0]
    expect(path).toBe('/api/v1/findings/bulk-dismissals/preview')
    expect(body).toMatchObject({ finding_ids: ['f1', 'f2', 'f3'], status: 'false_positive' })
    expect(body).not.toHaveProperty('idempotency_key')

    await userEvent.click(
      within(panel).getByText('4 need a second person: they go to approval (one request).')
    )
    expect(within(panel).getByText('SQL injection in login')).toBeInTheDocument()
    // 4 in the group, 1 listed.
    expect(within(panel).getByText('and 3 more')).toBeInTheDocument()
    expect(screen.getByTestId('bulk-dismiss-submit')).toHaveTextContent('Dismiss 42')
  })

  it('requires the note when the preview says so', async () => {
    post.mockResolvedValue(preview({ note_required: true, note_min_length: 10 }))
    renderDialog()
    await screen.findByText('38 will be dismissed now.')
    // 1 picks the first reason (the select itself is a Radix popup).
    fireEvent.keyDown(screen.getByTestId('bulk-dismiss-preview'), { key: '1' })
    expect(screen.getByLabelText('Note')).toBeInTheDocument()
    expect(
      screen.getByText('The approver reads it. Write at least 10 characters.')
    ).toBeInTheDocument()
    expect(screen.getByTestId('bulk-dismiss-submit')).toBeDisabled()
    // A digit typed in the note is text, not a reason.
    fireEvent.keyDown(screen.getByLabelText('Note'), { key: '3' })
    expect(screen.getByTestId('bulk-dismiss-reason')).toHaveTextContent(/scanner was wrong/i)
    await userEvent.type(screen.getByLabelText('Note'), 'Checked the TLS config')
    expect(screen.getByTestId('bulk-dismiss-submit')).toBeEnabled()
  })

  it('makes the note optional when the user decides all alone and none is serious', async () => {
    post.mockResolvedValue(
      preview({
        note_required: false,
        note_min_length: 0,
        counts: { decided: 5, grouped: 0, skipped: 0, budget_overflow: 0 },
      })
    )
    window.localStorage.setItem(
      'openctem.findings.dismiss.lastReason',
      JSON.stringify({ false_positive: 'test_or_example_code' })
    )
    renderDialog()
    await screen.findByText('5 will be dismissed now.')
    expect(screen.getByLabelText('Note (optional)')).toBeInTheDocument()
    // The last reason is preselected, so Dismiss is ready at once.
    expect(screen.getByTestId('bulk-dismiss-submit')).toBeEnabled()
    expect(screen.getByTestId('bulk-dismiss-submit')).toHaveTextContent('Dismiss 5')
  })

  it('offers a suppression rule instead above 500, without asking the server', async () => {
    const { onCreateRule } = renderDialog({
      selection: { kind: 'filter', filter: { severity: 'low' }, total: 1234 },
    })
    const box = screen.getByTestId('bulk-dismiss-too-large')
    expect(box).toHaveTextContent('1,234 findings match. Dismiss takes at most 500 at a time.')
    expect(screen.queryByTestId('bulk-dismiss-submit')).toBeNull()
    await userEvent.click(within(box).getByRole('button', { name: 'Create a suppression rule' }))
    expect(onCreateRule).toHaveBeenCalledWith()
    expect(post).not.toHaveBeenCalled()
  })

  it('shows the server count when it refuses the selection as too large', async () => {
    post.mockRejectedValue(
      new ApiClientError('too large', 'BULK_DISMISS_TOO_LARGE', 400, { count: 812, max: 500 })
    )
    renderDialog({ selection: { kind: 'filter', filter: { tool: 'nuclei' }, total: 400 } })
    expect(await screen.findByTestId('bulk-dismiss-too-large')).toHaveTextContent(
      '812 findings match'
    )
  })

  it('suggests a rule when most findings share one, prefilled', async () => {
    post.mockResolvedValue(
      preview({ same_rule: { tool: 'nuclei', rule_id: 'tls-version', count: 30, suggest: true } })
    )
    const { onCreateRule } = renderDialog()
    const hint = await screen.findByTestId('bulk-dismiss-rule-hint')
    expect(hint).toHaveTextContent('30 of these come from one rule (nuclei: tls-version)')
    await userEvent.click(within(hint).getByRole('button', { name: 'Create a rule instead' }))
    expect(onCreateRule).toHaveBeenCalledWith({
      tool_name: 'nuclei',
      rule_id: 'tls-version',
      suppression_type: 'false_positive',
    })
  })

  it('says the user will sign in again above the step-up threshold', async () => {
    post.mockResolvedValue(preview({ step_up_required: true }))
    renderDialog()
    expect(await screen.findByTestId('bulk-dismiss-stepup')).toHaveTextContent(
      'You will be asked to sign in again'
    )
  })

  it('asks again with the new count when the list changed', async () => {
    const filter = { kind: 'filter' as const, filter: { severity: 'low' }, total: 40 }
    post
      .mockRejectedValueOnce(new ApiClientError('changed', 'SELECTION_CHANGED', 409, { count: 37 }))
      .mockResolvedValue(
        preview({ counts: { decided: 37, grouped: 0, skipped: 0, budget_overflow: 0 } })
      )
    renderDialog({ selection: filter })
    expect(await screen.findByText('The list changed: 37 findings match now.')).toBeInTheDocument()
    expect(screen.getByTestId('bulk-dismiss-submit')).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Check the 37 again' }))
    await screen.findByText('37 will be dismissed now.')
    expect(post.mock.calls[1][1]).toMatchObject({ expected_count: 37 })
  })

  it('picks a reason with 1-7 and dismisses with Ctrl+Enter, one key across retries', async () => {
    post.mockImplementation((path: string) =>
      path.endsWith('/preview')
        ? Promise.resolve(preview({ note_required: false, note_min_length: 0 }))
        : Promise.reject(new ApiClientError('network', 'NETWORK_ERROR', 0))
    )
    const { onApplied } = renderDialog()
    await screen.findByText('38 will be dismissed now.')
    // The dialog opens on the reason picker, where digits pick a reason.
    expect(screen.getByTestId('bulk-dismiss-reason')).toHaveFocus()
    fireEvent.keyDown(screen.getByTestId('bulk-dismiss-reason'), { key: '2' })
    expect(screen.getByTestId('bulk-dismiss-reason')).toHaveTextContent(
      /test or (sample|example) code/i
    )
    fireEvent.keyDown(screen.getByTestId('bulk-dismiss-preview'), { key: 'Enter', ctrlKey: true })
    await waitFor(() => expect(callsTo('/api/v1/findings/bulk-dismissals')).toHaveLength(1))
    // The first try failed: the retry sends the same request with the same key.
    await waitFor(() => expect(screen.getByTestId('bulk-dismiss-submit')).toBeEnabled())
    post.mockImplementation((path: string) =>
      Promise.resolve(
        path.endsWith('/preview') ? preview() : preview({ status: 'applied', bulk_id: 'b1' })
      )
    )
    await userEvent.click(screen.getByTestId('bulk-dismiss-submit'))
    await waitFor(() => expect(onApplied).toHaveBeenCalled())
    const applies = callsTo('/api/v1/findings/bulk-dismissals')
    expect(applies).toHaveLength(2)
    expect(applies[0][1]).toMatchObject({ closure_reason: 'test_or_example_code' })
    expect(applies[0][1].idempotency_key).toBeTruthy()
    expect(applies[1][1].idempotency_key).toBe(applies[0][1].idempotency_key)
    // The reason is remembered for the next time.
    expect(window.localStorage.getItem('openctem.findings.dismiss.lastReason')).toContain(
      'test_or_example_code'
    )
  })

  it('asks for an end date when accepting the risk', async () => {
    post.mockResolvedValue(preview())
    renderDialog()
    await screen.findByText('38 will be dismissed now.')
    await userEvent.click(screen.getByRole('radio', { name: 'Accept the risk' }))
    expect(screen.getByLabelText('Reopens on')).toBeInTheDocument()
    await waitFor(() =>
      expect(post.mock.calls.at(-1)?.[1]).toMatchObject({
        status: 'accepted',
        closure_reason: 'risk_accepted',
      })
    )
    expect(post.mock.calls.at(-1)?.[1].expires_at).toMatch(/^\d{4}-\d\d-\d\dT/)
  })
})

describe('the Dismiss result toast', () => {
  it('offers Undo, which reopens and reports what it left alone', async () => {
    const onChanged = vi.fn()
    announceDismissResult(
      (k, f, p) => {
        void k
        let s = f ?? ''
        for (const [n, v] of Object.entries(p ?? {})) s = s.replaceAll(`{${n}}`, String(v))
        return s
      },
      preview({
        status: 'applied',
        bulk_id: 'bulk-1',
        counts: { decided: 3, grouped: 0, skipped: 0, budget_overflow: 0 },
      }),
      onChanged
    )
    expect(toastFns.success).toHaveBeenCalledTimes(1)
    const opts = toastFns.success.mock.calls[0][1]
    expect(opts.action.label).toBe('Undo')
    post.mockResolvedValue({
      bulk_id: 'bulk-1',
      reopened: ['a', 'b'],
      skipped: [{ id: 'c', reason: 'changed' }],
      group_canceled: false,
    })
    await act(async () => {
      opts.action.onClick()
    })
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(post).toHaveBeenCalledWith('/api/v1/findings/bulk-dismissals/bulk-1/reopen')
    expect(toastFns.warning).toHaveBeenCalledTimes(1)
  })

  it('offers Approve myself when nobody else can approve the group, Undo beside it', async () => {
    const open = vi.fn()
    const batch = { id: 'g-1', status: 'pending', self_approval_available: true }
    const load = vi.fn().mockResolvedValue(batch)
    await announceDismissResult(
      (_k, f) => f ?? '',
      preview({
        status: 'applied',
        bulk_id: 'bulk-2',
        grouped: { batch_id: 'g-1', count: 4, tier: 'standard' },
        counts: { decided: 0, grouped: 4, skipped: 0, budget_overflow: 0 },
      }),
      vi.fn(),
      { load, open } as never
    )
    expect(load).toHaveBeenCalledWith('g-1')
    const opts = [...toastFns.success.mock.calls, ...toastFns.warning.mock.calls][0][1]
    expect(opts.action.label).toBe('Approve myself')
    expect(opts.cancel.label).toBe('Undo')
    opts.action.onClick()
    expect(open).toHaveBeenCalledWith(batch)
  })

  it('keeps Undo as the action when another person can approve the group', async () => {
    const load = vi
      .fn()
      .mockResolvedValue({ id: 'g-1', status: 'pending', self_approval_available: false })
    await announceDismissResult(
      (_k, f) => f ?? '',
      preview({
        status: 'applied',
        bulk_id: 'bulk-3',
        grouped: { batch_id: 'g-1', count: 4, tier: 'standard' },
        counts: { decided: 0, grouped: 4, skipped: 0, budget_overflow: 0 },
      }),
      vi.fn(),
      { load, open: vi.fn() } as never
    )
    const opts = [...toastFns.success.mock.calls, ...toastFns.warning.mock.calls][0][1]
    expect(opts.action.label).toBe('Undo')
    expect(opts.cancel).toBeUndefined()
  })

  it('offers no Undo when nothing changed', () => {
    announceDismissResult(
      (_k, f) => f ?? '',
      preview({
        status: 'applied',
        bulk_id: 'b',
        counts: { decided: 0, grouped: 0, skipped: 2, budget_overflow: 0 },
      }),
      vi.fn()
    )
    expect(toastFns.error).toHaveBeenCalledWith(
      expect.any(String),
      expect.not.objectContaining({ action: expect.anything() })
    )
  })
})
