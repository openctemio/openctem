import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
const api = vi.hoisted(() => ({ create: vi.fn(), update: vi.fn(), updateOrg: vi.fn() }))
const mine = {
  id: 'd1',
  name: 'Executive',
  columns: 2,
  layout: [],
  is_default: false,
  description: '',
}
const list = vi.hoisted(() => ({ error: undefined as Error | undefined }))
vi.mock('@/features/dashboards/api/use-dashboards-api', () => ({
  useMyDashboards: () =>
    list.error
      ? { data: undefined, error: list.error, isLoading: false, mutate: vi.fn() }
      : { data: { data: [mine] }, isLoading: false, mutate: vi.fn() },
  useMyDashboard: () => ({ data: mine, isLoading: false }),
  useRevalidateDashboards: () => vi.fn(() => Promise.resolve()),
  createDashboard: api.create,
  updateDashboard: api.update,
  updateOrgDashboard: api.updateOrg,
  useOrgDashboard: (id: string | null) => ({
    data: id ? { ...mine, id, name: 'Org board', kind: 'organization' } : undefined,
    isLoading: false,
  }),
  useRevalidateAllDashboards: () => vi.fn(() => Promise.resolve()),
  deleteDashboard: vi.fn(),
  setDefaultDashboard: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('Dashboards page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    nav.search = ''
    list.error = undefined
    window.localStorage.clear()
    api.create.mockResolvedValue({ id: 'new' })
  })

  it('shows the column count of a dashboard, never the raw placeholder', () => {
    render(<DashboardsPage />)
    expect(screen.queryByText(/\{[a-z]+\} columns/)).toBeNull()
    expect(screen.getAllByText('2 columns').length).toBeGreaterThan(0)
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

  it('a template copy carries the template description and opens on the dashboard', async () => {
    render(<DashboardsPage />)
    const button = screen
      .getAllByRole('button', { name: 'Use template' })
      .find((b) => /executive/i.test(b.parentElement!.parentElement!.textContent ?? ''))!
    await userEvent.click(button)
    await waitFor(() => expect(api.create).toHaveBeenCalled())
    const input = api.create.mock.calls.at(-1)![0] as { description: string }
    expect(input.description).toMatch(/leadership/)
    await waitFor(() => expect(nav.push).toHaveBeenLastCalledWith('/'))
  })

  it('the edit form is addressed by ?edit=<id>, and Edit navigates there', async () => {
    const { unmount } = render(<DashboardsPage />)
    await userEvent.click(screen.getAllByRole('button', { name: /^Actions for / })[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Edit details' }))
    expect(nav.push).toHaveBeenCalledWith('/dashboards?edit=d1')
    unmount()
    nav.search = 'edit=d1'
    render(<DashboardsPage />)
    expect(await screen.findByRole('heading', { name: 'Edit dashboard' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(nav.push).toHaveBeenLastCalledWith('/dashboards')
  })

  it('an organization dashboard is edited with the organization endpoint and Back returns to it', async () => {
    nav.search = 'edit=o1&kind=organization'
    api.updateOrg.mockResolvedValue({})
    render(<DashboardsPage />)
    const name = await screen.findByLabelText(/Name/)
    expect(name).toHaveValue('Org board')
    await userEvent.clear(name)
    await userEvent.type(name, 'Leadership')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.updateOrg).toHaveBeenCalledTimes(1))
    expect(api.updateOrg.mock.calls[0][0]).toBe('o1')
    expect((api.updateOrg.mock.calls[0][1] as { name: string }).name).toBe('Leadership')
    expect(api.update).not.toHaveBeenCalled()
    await waitFor(() => expect(nav.push).toHaveBeenLastCalledWith('/'))
  })

  it('Customize (row menu) opens the dashboard in customize mode', async () => {
    render(<DashboardsPage />)
    await userEvent.click(screen.getAllByRole('button', { name: 'Actions for Executive' })[0])
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Customize' }))
    expect(nav.push).toHaveBeenCalledWith('/?customize=1')
  })

  it('lists my dashboards in one table; the name is a link that opens it', async () => {
    render(<DashboardsPage />)
    const table = screen.getByRole('table', { name: 'Your dashboards' })
    const link = within(table).getByRole('link', { name: 'Executive' })
    expect(link).toHaveAttribute('href', '/')
    await userEvent.click(link)
    expect(window.localStorage.getItem('openctem:dashboard-choice')).toBe('personal:d1')
  })

  it('a failed list read shows the error state with Retry, never "No dashboards yet"', () => {
    list.error = new Error('down')
    render(<DashboardsPage />)
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.queryByText(/No dashboards yet/)).toBeNull()
  })
})
