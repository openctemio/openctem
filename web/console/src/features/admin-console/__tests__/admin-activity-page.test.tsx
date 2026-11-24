import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TooltipProvider } from '@/components/ui/tooltip'

const mocks = vi.hoisted(() => ({ calls: [] as Record<string, unknown>[] }))

vi.mock('../api/use-admin-audit', async (orig) => ({
  ...(await orig<typeof import('../api/use-admin-audit')>()),
  useAdminAuditLogs: (query: Record<string, unknown>) => {
    mocks.calls.push(query)
    return {
      isLoading: false,
      isValidating: false,
      error: undefined,
      mutate: vi.fn(),
      data: {
        data: [
          {
            id: 'a1',
            admin_email: 'ann@corp.example',
            action: 'console.login',
            success: true,
            created_at: '2026-11-01T10:00:00Z',
          },
        ],
        total: 1,
        total_pages: 1,
      },
    }
  },
}))
vi.mock('../components/admin-audit-chain-status', () => ({
  AdminAuditChainStatus: () => null,
  AdminAuditChainBadge: () => null,
}))
vi.mock('../components/admin-audit-detail-sheet', () => ({ AdminAuditDetailSheet: () => null }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { default: ActivityPage } = await import('@console/app/(console)/security/activity/page')

const renderPage = () =>
  render(
    <TooltipProvider>
      <ActivityPage />
    </TooltipProvider>
  )

beforeEach(() => {
  mocks.calls.length = 0
  window.history.replaceState(null, '', '/security/activity')
})

describe('Admin activity page', () => {
  it('keeps the kind view and Result in the toolbar; the rest is behind Add filter', () => {
    renderPage()
    const toolbar = screen.getByTestId('data-table-toolbar')
    expect(within(toolbar).getByRole('button', { name: /add filter/i })).toBeInTheDocument()
    expect(within(toolbar).getByRole('button', { name: /Which events/ })).toBeInTheDocument()
    expect(within(toolbar).getByRole('button', { name: /result/i })).toBeInTheDocument()
    // Action, administrator and the dates are not toolbar fields any more.
    expect(screen.queryByRole('textbox', { name: 'Filter by action' })).toBeNull()
    expect(screen.queryByLabelText('From date')).toBeNull()
  })

  it('shows the URL filters as chips and sends the same request filters', async () => {
    window.history.replaceState(
      null,
      '',
      '/security/activity?action=console.login&admin_email=ann%40corp.example&from=2026-11-01'
    )
    renderPage()
    const chips = screen.getByTestId('activity-filter-chips')
    expect(within(chips).getByText('Action: console.login')).toBeInTheDocument()
    expect(within(chips).getByText('Administrator: ann@corp.example')).toBeInTheDocument()
    expect(within(chips).getByText('From: 2026-11-01')).toBeInTheDocument()
    await waitFor(() =>
      expect(mocks.calls.at(-1)).toMatchObject({
        action: 'console.login',
        adminEmail: 'ann@corp.example',
      })
    )
    expect(mocks.calls.at(-1)?.from).toBeTruthy()
  })

  it('removes one filter from its chip, keeping the others', async () => {
    window.history.replaceState(null, '', '/security/activity?action=console.login&to=2026-11-02')
    renderPage()
    await userEvent.click(
      screen.getByRole('button', { name: 'Remove filter Action: console.login' })
    )
    await waitFor(() => expect(window.location.search).not.toContain('action='))
    expect(window.location.search).toContain('to=2026-11-02')
    expect(screen.queryByText('Action: console.login')).toBeNull()
    expect(screen.getByText('To: 2026-11-02')).toBeInTheDocument()
  })

  it('sets a filter from the Add filter panel into the URL', async () => {
    renderPage()
    await userEvent.click(screen.getByRole('button', { name: /add filter/i }))
    const field = await screen.findByRole('textbox', { name: 'Filter by administrator' })
    expect(screen.getByRole('textbox', { name: 'Filter by action' })).toBeInTheDocument()
    expect(screen.getByLabelText('From date')).toBeInTheDocument()
    expect(screen.getByLabelText('To date')).toBeInTheDocument()
    await userEvent.type(field, 'bob')
    await waitFor(() => expect(window.location.search).toContain('admin_email=bob'))
  })
})
