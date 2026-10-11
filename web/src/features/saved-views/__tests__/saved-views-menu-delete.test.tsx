import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { SavedViewsMenu } from '../components/saved-views-menu'
import { deleteSavedView, type SavedView } from '../api/use-saved-views'

const view = {
  id: 'v1',
  name: 'Critical internet-facing',
  is_owner: true,
  group_name: '',
} as unknown as SavedView

vi.mock('../api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('../api/use-saved-views')>()),
  useSavedViews: () => ({ views: [view], mutate: vi.fn() }),
  deleteSavedView: vi.fn(() => Promise.resolve()),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useMyGroups: () => ({ groups: [] }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('SavedViewsMenu delete', () => {
  beforeEach(() => vi.mocked(deleteSavedView).mockClear())

  it('one click on the trash icon asks first; only Delete deletes', async () => {
    const onSelect = vi.fn()
    render(<SavedViewsMenu page="findings" onSelect={onSelect} />)
    await userEvent.click(screen.getByRole('button', { name: /saved views|views/i }))
    await userEvent.click(
      await screen.findByRole('button', { name: 'Delete view Critical internet-facing' })
    )

    expect(deleteSavedView).not.toHaveBeenCalled()
    expect(onSelect).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete view "Critical internet-facing"?')

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(deleteSavedView).toHaveBeenCalledWith('v1'))
  })

  it('Cancel keeps the view', async () => {
    render(<SavedViewsMenu page="findings" onSelect={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /saved views|views/i }))
    await userEvent.click(
      await screen.findByRole('button', { name: 'Delete view Critical internet-facing' })
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
    expect(deleteSavedView).not.toHaveBeenCalled()
  })
})
