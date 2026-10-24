/**
 * Actions that change many findings at once, or send traffic, ask first: the
 * request is not sent until the dialog is confirmed.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const post = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  post,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

import { VerifyGroupActions } from '../verify-group-actions'
import { AutoAssignDialog } from '../auto-assign-dialog'

const group = {
  group_key: 'CVE-2026-1',
  label: 'CVE-2026-1',
  stats: { fix_applied: 3 },
} as unknown as Parameters<typeof VerifyGroupActions>[0]['group']

beforeEach(() => post.mockReset())

describe('VerifyGroupActions', () => {
  it('asks before approving the fixes and states the count', async () => {
    post.mockResolvedValue({ updated: 3 })
    render(<VerifyGroupActions group={group} />)
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(post).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Verify 3 fixes of "CVE-2026-1"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Verify 3 fixes' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0][0]).toContain('/findings/actions/verify')
  })

  it('does not reject without a reason, and counts the fixes on the button', async () => {
    post.mockResolvedValue({ updated: 3 })
    render(<VerifyGroupActions group={group} />)
    await userEvent.click(screen.getByRole('button', { name: 'Reject' }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Reject 3 fixes' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'still present')
    expect(confirm).toBeEnabled()
    await userEvent.click(confirm)
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0][1]).toMatchObject({ reason: 'still present' })
  })
})

describe('AutoAssignDialog', () => {
  it('sends nothing until the confirm button is pressed', async () => {
    post.mockResolvedValue({ assigned: 4, by_owner: { a: 4 }, unassigned: 0 })
    const onOpenChange = vi.fn()
    render(<AutoAssignDialog open onOpenChange={onOpenChange} />)
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Assign unassigned findings to their asset owners?')
    expect(post).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Assign to owners' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0][0]).toContain('assign-to-owners')
  })
})
