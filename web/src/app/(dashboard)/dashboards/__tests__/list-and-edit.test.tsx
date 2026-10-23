import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import DashboardsPage from '../page'

const nav = vi.hoisted(() => ({ push: vi.fn(), search: '' }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: nav.push }),
  useSearchParams: () => new URLSearchParams(nav.search),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
const api = vi.hoisted(() => ({ create: vi.fn() }))
const mine = {
  id: 'd1',
  name: 'Executive',
  columns: 2,
  layout: [],
  is_default: false,
  description: '',
}
vi.mock('@/features/dashboards/api/use-dashboards-api', () => ({
  useMyDashboards: () => ({ data: { data: [mine] }, isLoading: false }),
  useMyDashboard: () => ({ data: mine, isLoading: false }),
  useRevalidateDashboards: () => vi.fn(() => Promise.resolve()),
  createDashboard: api.create,
  updateDashboard: vi.fn(),
  deleteDashboard: vi.fn(),
  setDefaultDashboard: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('Dashboards page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    nav.search = ''
    api.create.mockResolvedValue({ id: 'new' })
  })

  it('a template whose name is taken is created with a numbered name', async () => {
    render(<DashboardsPage />)
    const button = screen
      .getAllByRole('button', { name: 'Use template' })
      .find((b) => /executive/i.test(b.parentElement!.parentElement!.textContent ?? ''))!
    await userEvent.click(button)
    await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
    expect((api.create.mock.calls[0][0] as { name: string }).name).toMatch(/ 2$/)
  })

  it('the edit form is addressed by ?edit=<id>, and Edit navigates there', async () => {
    const { unmount } = render(<DashboardsPage />)
    await userEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0])
    expect(nav.push).toHaveBeenCalledWith('/dashboards?edit=d1')
    unmount()
    nav.search = 'edit=d1'
    render(<DashboardsPage />)
    expect(await screen.findByRole('heading', { name: 'Edit dashboard' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(nav.push).toHaveBeenLastCalledWith('/dashboards')
  })

  it('Customize opens the dashboard in customize mode', async () => {
    render(<DashboardsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Customize' }))
    expect(nav.push).toHaveBeenCalledWith('/?customize=1')
  })
})
