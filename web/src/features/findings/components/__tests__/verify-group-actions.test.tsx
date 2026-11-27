import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'

const post = vi.fn()
vi.mock('@/lib/api/client', () => ({ post: (...a: unknown[]) => post(...a) }))
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), warning: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

import { VerifyGroupActions } from '../verify-group-actions'
import type { FindingGroup } from '../../api/use-finding-groups'

const group = {
  group_key: 'CVE-2020-7471',
  label: 'CVE-2020-7471',
  stats: { total: 1, open: 0, in_progress: 0, fix_applied: 1, resolved: 0 },
} as unknown as FindingGroup

async function approve() {
  fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
  fireEvent.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Verify 1 fix' })
  )
}

beforeEach(() => {
  post.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
  toast.warning.mockReset()
})

// Production report: Approve on a group whose one finding was critical showed
// a green "0 findings verified" and nothing changed.
describe('VerifyGroupActions', () => {
  it('approves the group by its CVE and says why nothing was verified', async () => {
    post.mockResolvedValue({
      updated: 0,
      refused: 1,
      reasons: { evidence_required: 1 },
      rows: [{ finding_id: 'f1', code: 'evidence_required' }],
    })
    const onDone = vi.fn()
    render(<VerifyGroupActions group={group} onDone={onDone} />)
    await approve()
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
    expect(post).toHaveBeenCalledWith(
      '/api/v1/findings/actions/verify',
      expect.objectContaining({ filter: { cve_ids: ['CVE-2020-7471'] } })
    )
    expect(toast.success).not.toHaveBeenCalled()
    expect(String(toast.error.mock.calls[0][0])).toMatch(/^Nothing was verified: A critical/)
    expect(onDone).toHaveBeenCalled()
  })

  it('warns on a partial verify', async () => {
    post.mockResolvedValue({ updated: 2, refused: 1, reasons: { checklist_required: 1 } })
    render(<VerifyGroupActions group={group} />)
    await approve()
    await waitFor(() => expect(toast.warning).toHaveBeenCalled())
    expect(toast.warning.mock.calls[0][0]).toBe('2 of 3 verified')
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('is a success only when every finding was verified', async () => {
    post.mockResolvedValue({ updated: 1, refused: 0, reasons: {}, rows: [] })
    render(<VerifyGroupActions group={group} />)
    await approve()
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('1 finding verified', undefined))
  })
})
