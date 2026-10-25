import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { Capability } from '@/lib/api/capability-types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const state = vi.hoisted(() => ({
  usage: { tool_count: 2, sensor_count: 1, tool_names: ['nuclei'], sensor_names: ['hq'] } as {
    tool_count: number
    sensor_count: number
    tool_names?: string[]
    sensor_names?: string[]
  },
  deleteCap: vi.fn(),
}))

const cap = {
  id: 'cap1',
  name: 'web-crawl',
  display_name: 'Web crawl',
  is_builtin: false,
  category: 'web',
} as unknown as Capability

vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (key: string, fallback: string) => [key === 'tab' ? 'custom' : fallback, vi.fn()],
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useCanMutate: () => true,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/api/capability-hooks', () => ({
  useAllCapabilities: () => ({
    data: { items: [cap] },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCapabilityUsageStats: () => ({ data: state.usage, isLoading: false }),
  useDeleteCapability: () => ({ trigger: state.deleteCap, isMutating: false }),
  invalidateCapabilitiesCache: vi.fn(async () => undefined),
}))
vi.mock('../components/capability-table', () => ({
  CapabilityTable: ({ onDelete }: { onDelete?: (c: Capability) => void }) => (
    <button onClick={() => onDelete?.(cap)}>delete-row</button>
  ),
}))
vi.mock('../components/capability-card', () => ({ CapabilityCard: () => null }))
vi.mock('../components/create-capability-dialog', () => ({ CreateCapabilityDialog: () => null }))
vi.mock('../components/edit-capability-dialog', () => ({ EditCapabilityDialog: () => null }))
vi.mock('../components/capability-detail-panel', () => ({ CapabilityDetailPanel: () => null }))

import { CapabilitiesSection } from '../components/capabilities-section'

describe('capability delete', () => {
  beforeEach(() => state.deleteCap.mockReset().mockResolvedValue(undefined))

  it('a capability in use lists its impact and force-deletes only after the name is typed', async () => {
    const user = userEvent.setup()
    render(<CapabilitiesSection />)
    await user.click(screen.getByRole('button', { name: 'delete-row' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the capability Web crawl?')
    expect(dialog).toHaveTextContent('This capability is in use')
    expect(dialog).toHaveTextContent('nuclei')
    const confirm = within(dialog).getByRole('button', { name: 'Force delete' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'Web crawl')
    await user.click(confirm)
    await waitFor(() => expect(state.deleteCap).toHaveBeenCalledWith({ force: true }))
  })

  it('an unused capability also needs the name, and is not forced', async () => {
    state.usage = { tool_count: 0, sensor_count: 0 }
    const user = userEvent.setup()
    render(<CapabilitiesSection />)
    await user.click(screen.getByRole('button', { name: 'delete-row' }))
    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Delete capability' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'Web crawl')
    await user.click(confirm)
    await waitFor(() => expect(state.deleteCap).toHaveBeenCalledWith({ force: false }))
  })
})
