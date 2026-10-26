import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ExposureBulkActions } from '../exposure-state-actions'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))

beforeEach(() => {
  toast.success.mockReset()
  toast.error.mockReset()
  toast.info.mockReset()
})

async function acceptWith(outcome: {
  total: number
  succeeded: number
  pending: number
  failed: number
}) {
  render(
    <ExposureBulkActions
      selectedIds={['e1', 'e2', 'e3']}
      onClearSelection={vi.fn()}
      onBulkResolve={vi.fn()}
      onBulkAccept={vi.fn(() => Promise.resolve(outcome))}
      onBulkFalsePositive={vi.fn()}
    />
  )
  await userEvent.click(screen.getByRole('button', { name: /Accept risk/ }))
  await userEvent.type(await screen.findByRole('textbox'), 'reason')
  const dialog = screen.getByRole('alertdialog')
  const buttons = Array.from(dialog.querySelectorAll('button'))
  await userEvent.click(buttons[buttons.length - 1])
}

describe('bulk accept toasts', () => {
  it('gives no success toast for items that went to pending approval', async () => {
    await acceptWith({ total: 3, succeeded: 3, pending: 3, failed: 0 })
    await waitFor(() => expect(toast.info).toHaveBeenCalled())
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('reports applied items, pending items and failures separately', async () => {
    await acceptWith({ total: 3, succeeded: 2, pending: 1, failed: 1 })
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('1 of 3 failed.'))
    expect(toast.success).toHaveBeenCalledWith('1 exposures accepted.')
    expect(toast.info).toHaveBeenCalled()
  })
})
