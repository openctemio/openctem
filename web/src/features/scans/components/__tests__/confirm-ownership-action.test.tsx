import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ConfirmOwnershipAction } from '../confirm-ownership-action'
import { TargetOutcomes } from '../target-outcomes'

const post = vi.fn()
const can = vi.fn()

vi.mock('@/lib/api/client', () => ({
  get: vi.fn(),
  post: (...args: unknown[]) => post(...args),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsRead: 'assets:read', AssetsWrite: 'assets:write' },
  usePermissions: () => ({ can }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

describe('ConfirmOwnershipAction', () => {
  beforeEach(() => {
    post.mockReset()
    can.mockReset()
    post.mockResolvedValue({ decided: [{ asset_id: 'a' }], not_found: [] })
  })

  it('confirms the listed names with the confirmed decision', async () => {
    can.mockReturnValue(true)
    const onDone = vi.fn()
    render(<ConfirmOwnershipAction names={['a.example.com', 'b.example.com']} onDone={onDone} />)
    await userEvent.click(
      screen.getByRole('button', { name: 'Confirm ownership of 2 listed names' })
    )
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post).toHaveBeenCalledWith('/api/v1/easm/candidates/decisions', {
      asset_ids: [],
      asset_names: ['a.example.com', 'b.example.com'],
      state: 'confirmed',
    })
    await waitFor(() => expect(onDone).toHaveBeenCalled())
  })

  it('is not offered to a caller who may not write assets', () => {
    can.mockReturnValue(false)
    render(<ConfirmOwnershipAction names={['a.example.com']} />)
    expect(screen.queryByTestId('confirm-ownership')).not.toBeInTheDocument()
  })

  it('appears in the unconfirmed and wildcard groups, and nowhere else', async () => {
    can.mockReturnValue(true)
    render(
      <TargetOutcomes
        willScan={0}
        groups={[
          {
            reason: 'ownership_unconfirmed',
            tone: 'warning',
            count: 2,
            targets: ['a.example.com'],
          },
          { reason: 'wildcard_only', tone: 'warning', count: 1, targets: ['w.example.com'] },
          { reason: 'unresolved', tone: 'info', count: 1, targets: ['gone.example.com'] },
        ]}
      />
    )
    for (const row of screen.getAllByRole('button', { expanded: false })) await userEvent.click(row)
    expect(screen.getAllByTestId('confirm-ownership')).toHaveLength(2)
    expect(screen.getAllByText(/Required on platform sensors of the hosted service/)).toHaveLength(
      1
    )
  })
})
