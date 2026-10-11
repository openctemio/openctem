import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { deleteDashboard } from '@/features/dashboards/api/use-dashboards-api'
import DashboardsPage from '../page'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/dashboards/api/use-dashboards-api', () => ({
  useMyDashboards: () => ({
    data: {
      data: [{ id: 'd1', name: 'Ops wallboard', columns: 2, layout: [], is_default: false }],
    },
    isLoading: false,
  }),
  useMyDashboard: () => ({ data: undefined, isLoading: false }),
  useRevalidateDashboards: () => vi.fn(),
  createDashboard: vi.fn(),
  updateDashboard: vi.fn(),
  deleteDashboard: vi.fn(() => Promise.resolve()),
  setDefaultDashboard: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('Dashboards list delete', () => {
  it('asks before deleting a dashboard and names it', async () => {
    render(<DashboardsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Delete dashboard Ops wallboard' }))
    expect(deleteDashboard).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete dashboard "Ops wallboard"?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(deleteDashboard).toHaveBeenCalledWith('d1'))
  })
})
