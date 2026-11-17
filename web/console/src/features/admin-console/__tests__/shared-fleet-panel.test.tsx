import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { actOnSharedSensor } from '../api/use-shared-fleet'
import { SharedFleetPanel } from '../components/shared-fleet-panels'

const state = vi.hoisted(() => ({ role: 'readonly' as string }))
vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => ({ role: state.role }),
  useAdminOrNull: () => ({ role: state.role }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../api/use-shared-fleet', async (orig) => ({
  ...(await orig<typeof import('../api/use-shared-fleet')>()),
  actOnSharedSensor: vi.fn(),
  useSharedFleet: () => ({
    isLoading: false,
    mutate: vi.fn(),
    data: {
      sensors: [
        {
          id: 's1',
          name: 'shared-eu-1',
          region: 'eu',
          status: 'active',
          health: 'online',
          version: 'v1.2.3',
          tools: ['nuclei', 'httpx'],
          current_jobs: 1,
          max_jobs: 4,
          created_at: '2026-10-01T00:00:00Z',
        },
      ],
    },
  }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  vi.clearAllMocks()
  state.role = 'readonly'
})

describe('SharedFleetPanel', () => {
  it('is a named table, the sensor and its region on one line, no action for a read-only administrator', () => {
    render(<SharedFleetPanel />)
    const table = screen.getByRole('table', { name: 'Fleet' })
    const row = within(table).getAllByRole('row')[1]
    expect(within(row).getByText('shared-eu-1')).toBeInTheDocument()
    expect(within(row).getByText('eu')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Actions for the sensor/ })).toBeNull()
  })

  it('offers a super admin Pause and Retire in the row menu, each through its confirmation', async () => {
    state.role = 'super_admin'
    const user = userEvent.setup()
    render(<SharedFleetPanel />)
    await user.click(screen.getByRole('button', { name: 'Actions for the sensor shared-eu-1' }))
    expect(await screen.findByRole('menuitem', { name: /Pause/ })).toBeInTheDocument()
    await user.click(screen.getByRole('menuitem', { name: /Retire/ }))
    // The same typed confirmation as before: nothing is sent until it is filled.
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(actOnSharedSensor).not.toHaveBeenCalled()
  })
})
