import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { SuppressionDetailSheet } from '../components/suppression-detail-sheet'
import type { SuppressionRule } from '../types'

let canApprove = true
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => canApprove,
}))

const rule = {
  id: 'r1',
  tenant_id: 't1',
  name: 'legacy rule',
  suppression_type: 'false_positive',
  rule_id: 'go.legacy',
  status: 'approved',
  requested_by: 'u1',
  requested_at: '2026-01-01T00:00:00Z',
  expires_at: '2027-01-13T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  review_flagged_at: '2026-10-15T00:00:00Z',
  review_reason: 'no_end_date',
} as SuppressionRule

describe('suppression review flag', () => {
  it('lets an approver mark a flagged rule as reviewed', async () => {
    canApprove = true
    const onReviewed = vi.fn()
    render(
      <SuppressionDetailSheet rule={rule} open onOpenChange={() => {}} onReviewed={onReviewed} />
    )
    expect(screen.getByText('Review this rule')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Mark as reviewed/ }))
    expect(onReviewed).toHaveBeenCalledWith(rule)
  })

  it('offers no button without the approve permission', () => {
    canApprove = false
    render(<SuppressionDetailSheet rule={rule} open onOpenChange={() => {}} onReviewed={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /Mark as reviewed/ })).toBeNull()
  })
})
