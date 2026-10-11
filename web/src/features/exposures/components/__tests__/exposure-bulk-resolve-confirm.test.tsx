import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ExposureBulkActions } from '../exposure-state-actions'

vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function setup() {
  const onBulkResolve = vi.fn(() => Promise.resolve())
  const onClearSelection = vi.fn()
  render(
    <ExposureBulkActions
      selectedIds={['e1', 'e2', 'e3']}
      onClearSelection={onClearSelection}
      onBulkResolve={onBulkResolve}
      onBulkAccept={vi.fn()}
      onBulkFalsePositive={vi.fn()}
    />
  )
  return { onBulkResolve, onClearSelection }
}

describe('ExposureBulkActions resolve', () => {
  it('one click on Resolve asks first and states the count', async () => {
    const { onBulkResolve } = setup()
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(onBulkResolve).not.toHaveBeenCalled()
    expect(await screen.findByRole('alertdialog')).toHaveTextContent('Resolve 3 exposures?')
  })

  it('confirming resolves the selected exposures', async () => {
    const { onBulkResolve, onClearSelection } = setup()
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(
      Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Resolve')!
    )
    await waitFor(() => expect(onBulkResolve).toHaveBeenCalledWith(['e1', 'e2', 'e3']))
    expect(onClearSelection).toHaveBeenCalled()
  })

  it('Cancel resolves nothing', async () => {
    const { onBulkResolve } = setup()
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(onBulkResolve).not.toHaveBeenCalled()
  })
})
