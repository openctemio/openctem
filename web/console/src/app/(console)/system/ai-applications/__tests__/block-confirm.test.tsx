import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { setMcpClientBlocked } from '@console/features/admin-console/api/use-mcp-clients'
import AiApplicationsPage from '../page'

const clients = vi.hoisted(() => ({
  list: [] as Array<Record<string, unknown>>,
  calls: [] as unknown[][],
  total: 1,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@console/features/admin-console/components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'super_admin' }),
}))
vi.mock('@console/features/admin-console/api/use-mcp-clients', () => ({
  useMcpClients: (...args: unknown[]) => ({
    data: (clients.calls.push(args), { data: clients.list, total: clients.total, total_pages: 3 }),
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  setMcpClientBlocked: vi.fn(() => Promise.resolve()),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const client = (blocked: boolean) => ({
  id: 'c1',
  client_id: 'cid',
  name: 'Desk Assistant',
  kind: 'dynamic',
  redirect_uris: [],
  blocked,
  created_at: '2026-10-01T00:00:00Z',
  active_connections: 4,
  organizations: 2,
})

describe('AI applications block', () => {
  it('blocking everywhere asks first', async () => {
    clients.list = [client(false)]
    render(<AiApplicationsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Block' }))
    expect(setMcpClientBlocked).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Block Desk Assistant everywhere?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Block application' }))
    await waitFor(() => expect(setMcpClientBlocked).toHaveBeenCalledWith('c1', true))
  })

  it('unblocking everywhere asks first too (it lets the application back in)', async () => {
    vi.mocked(setMcpClientBlocked).mockClear()
    clients.list = [client(true)]
    render(<AiApplicationsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Unblock' }))
    expect(setMcpClientBlocked).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Unblock Desk Assistant everywhere?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Unblock application' }))
    await waitFor(() => expect(setMcpClientBlocked).toHaveBeenCalledWith('c1', false))
  })

  it('pages on the server and shows the host before the declared name', () => {
    clients.calls = []
    clients.list = [
      { ...client(false), kind: 'metadata_document', host: 'evil.example', name: 'Trusted Corp' },
    ]
    clients.total = 120
    render(<AiApplicationsPage />)
    // First page, page size 25, no search, no blocked filter.
    expect(clients.calls[0]).toEqual(['', null, 1, 25])
    expect(screen.getByText('evil.example')).toBeInTheDocument()
    expect(screen.getByText('Declares itself as Trusted Corp')).toBeInTheDocument()
    expect(screen.getByText('4 active connections')).toBeInTheDocument()
    expect(screen.getByText('2 organizations')).toBeInTheDocument()
  })
})
