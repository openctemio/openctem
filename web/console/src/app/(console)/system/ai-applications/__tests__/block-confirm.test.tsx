import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { setMcpClientBlocked } from '@console/features/admin-console/api/use-mcp-clients'
import AiApplicationsPage from '../page'

const clients = vi.hoisted(() => ({
  list: [] as Array<Record<string, unknown>>,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@console/features/admin-console/components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'super_admin' }),
}))
vi.mock('@console/features/admin-console/api/use-mcp-clients', () => ({
  useMcpClients: () => ({
    data: { data: clients.list },
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
    await userEvent.click(within(dialog).getByRole('button', { name: 'Block' }))
    await waitFor(() => expect(setMcpClientBlocked).toHaveBeenCalledWith('c1', true))
  })

  it('unblocking needs no confirmation', async () => {
    vi.mocked(setMcpClientBlocked).mockClear()
    clients.list = [client(true)]
    render(<AiApplicationsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Unblock' }))
    await waitFor(() => expect(setMcpClientBlocked).toHaveBeenCalledWith('c1', false))
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })
})
