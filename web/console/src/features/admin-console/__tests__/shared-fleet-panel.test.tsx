import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { actOnSharedSensor } from '../api/use-shared-fleet'
import { SharedFleetMobileCard, SharedFleetPanel } from '../components/shared-fleet-panels'

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
    const table = screen.getByRole('table', { name: 'Sensors' })
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

describe('SharedFleetMobileCard', () => {
  const base = {
    id: 's2',
    name: 'shared-ap-southeast-very-long-sensor-name-01',
    region: 'ap',
    status: 'disabled' as const,
    health: 'offline' as const,
    version: '',
    tools: [] as string[],
    current_jobs: 0,
    max_jobs: 0,
    created_at: '2026-10-01T00:00:00Z',
  }

  it('shows fixed slots: name and region, the state chips on a wrapping line, one facts line', () => {
    const { container } = render(<SharedFleetMobileCard sensor={base} />)
    expect(container.querySelector('[data-slot="fleet-card-title"]')).toHaveTextContent(
      `${base.name}ap`
    )
    const state = container.querySelector('[data-slot="fleet-card-state"]') as HTMLElement
    // The chips wrap instead of being cut at the card edge.
    expect(state.className).toContain('flex-wrap')
    expect(state.className).not.toContain('overflow-hidden')
    expect(within(state).getByText('Paused')).toBeInTheDocument()
    expect(within(state).getByText('Offline')).toBeInTheDocument()
    const facts = container.querySelector('[data-slot="meta-line"]') as HTMLElement
    expect(facts).toHaveTextContent('0 jobs')
    expect(facts).toHaveTextContent('Not seen yet')
  })

  it('leaves out an empty version and tools instead of showing a dash, and has no label/value grid', () => {
    const { container } = render(<SharedFleetMobileCard sensor={base} />)
    expect(container).not.toHaveTextContent(/\bv\d/)
    expect(
      Array.from(container.querySelectorAll('span, p')).some((e) => e.textContent?.trim() === '-')
    ).toBe(false)
    expect(container.querySelector('[data-slot="fleet-card-tools"]')).toBeNull()
    expect(container.querySelector('dl, dt, dd')).toBeNull()
  })

  it('shows the version, jobs against capacity, last seen and the tools when present', () => {
    const { container } = render(
      <SharedFleetMobileCard
        sensor={{
          ...base,
          version: 'v1.2.3',
          tools: ['nuclei', 'httpx'],
          current_jobs: 1,
          max_jobs: 4,
          last_seen_at: new Date().toISOString(),
        }}
      />
    )
    const facts = container.querySelector('[data-slot="meta-line"]') as HTMLElement
    expect(facts).toHaveTextContent('v1.2.3')
    expect(facts).toHaveTextContent('1 of 4 jobs')
    expect(facts).toHaveTextContent('Seen')
    expect(container.querySelector('[data-slot="fleet-card-tools"]')).toHaveTextContent(
      'nuclei, httpx'
    )
  })
})
