import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

let show = ''
const setUrl = vi.hoisted(() => vi.fn())
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_key: string, fallback: string) => [show || fallback, setUrl],
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const sim = (id: string, over: Record<string, unknown>) => ({
  id,
  name: `Sim ${id}`,
  status: 'active',
  last_result: '',
  detection_rate: 50,
  mitre_technique_id: '',
  mitre_technique_name: '',
  mitre_tactic: '',
  simulation_type: 'atomic',
  last_run_at: '',
  ...over,
})

vi.mock('@/features/simulation/api/use-simulation-api', () => ({
  useSimulations: () => ({
    data: {
      data: [
        sim('a', { last_result: 'bypassed' }),
        sim('b', { last_result: 'detected' }),
        sim('c', { status: 'draft' }),
      ],
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useRunSimulation: () => ({ trigger: vi.fn() }),
}))

const { default: AttackSimulationPage } = await import('../page')

beforeEach(() => {
  show = ''
  setUrl.mockReset()
})

describe('attack simulation metric strip', () => {
  it('has only filter tiles (no averages) and toggles the bypassed filter', async () => {
    render(<AttackSimulationPage />)
    const tiles = document.querySelectorAll('[data-slot="metric-strip"] button')
    expect(tiles).toHaveLength(4)
    expect(screen.queryByText(/Avg detection rate/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /Bypassed/ }))
    expect(setUrl).toHaveBeenCalledWith('bypassed')
  })

  it('lists only bypassed simulations when the bypassed filter is on', () => {
    show = 'bypassed'
    render(<AttackSimulationPage />)
    expect(screen.getByText('Sim a')).toBeInTheDocument()
    expect(screen.queryByText('Sim b')).toBeNull()
    expect(screen.queryByText('Sim c')).toBeNull()
  })
})
