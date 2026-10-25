import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { Integration } from '@/features/integrations'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const del = vi.hoisted(() => vi.fn())
vi.mock('@/features/integrations', () => ({
  useDeleteIntegrationApi: () => ({ trigger: del, isMutating: false }),
  useTestIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateSCMIntegrationsCache: vi.fn(async () => undefined),
}))
vi.mock('../components/sync-repositories-dialog', () => ({ SyncRepositoriesDialog: () => null }))
vi.mock('../components/edit-connection-dialog', () => ({ EditConnectionDialog: () => null }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { SCMConnectionCard } from '../components/scm-connection-card'

const connection = {
  id: 'c1',
  name: 'acme-github',
  provider: 'github',
  category: 'scm',
  status: 'connected',
  config: {},
} as unknown as Integration

describe('SCMConnectionCard delete', () => {
  beforeEach(() => del.mockReset().mockResolvedValue(undefined))

  it('asks for the connection name before deleting', async () => {
    const user = userEvent.setup()
    const { container } = render(<SCMConnectionCard connection={connection} repositoryCount={3} />)
    await user.click(container.querySelector('button[aria-haspopup="menu"]') as HTMLElement)
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the SCM connection "acme-github"?')
    expect(dialog).toHaveTextContent('3 repositories')
    const confirm = within(dialog).getByRole('button', { name: 'Delete connection' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'acme-github')
    await user.click(confirm)
    await waitFor(() => expect(del).toHaveBeenCalledTimes(1))
  })
})
