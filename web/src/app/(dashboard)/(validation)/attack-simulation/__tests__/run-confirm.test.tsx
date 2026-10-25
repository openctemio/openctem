/** Run sends live safe-check traffic: nothing is dispatched until it is confirmed. */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const runSimulation = vi.hoisted(() => vi.fn())
vi.mock('@/features/simulation/api/use-simulation-api', () => ({
  useSimulations: () => ({
    data: {
      data: [
        {
          id: 's-1',
          name: 'Credential dumping',
          status: 'active',
          simulation_type: 'atomic',
          mitre_technique_id: 'T1003',
          mitre_technique_name: 'OS Credential Dumping',
          last_result: '',
          detection_rate: 0,
          last_run_at: null,
        },
      ],
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useRunSimulation: () => ({ trigger: runSimulation }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import AttackSimulationPage from '../page'

describe('Attack simulation Run', () => {
  it('dispatches only after the confirmation', async () => {
    runSimulation.mockResolvedValue({ result: 'detected' })
    render(<AttackSimulationPage />)
    await userEvent.click(await screen.findByRole('button', { name: 'Run' }))
    expect(runSimulation).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Run the simulation "Credential dumping" now?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Run simulation' }))
    await waitFor(() => expect(runSimulation).toHaveBeenCalledWith('s-1'))
  })

  it('Cancel dispatches nothing', async () => {
    runSimulation.mockReset()
    render(<AttackSimulationPage />)
    await userEvent.click(await screen.findByRole('button', { name: 'Run' }))
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel' })
    )
    expect(runSimulation).not.toHaveBeenCalled()
  })
})
