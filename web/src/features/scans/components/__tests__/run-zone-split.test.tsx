import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('@/features/shared', () => ({
  RunStatusBadge: ({ status }: { status: string }) => <span>{status}</span>,
}))

import { RunZoneSplitPanel } from '../run-zone-split'

describe('RunZoneSplitPanel', () => {
  it('lists one row per zone with its zone run', () => {
    render(
      <RunZoneSplitPanel
        split={{
          groups: [
            {
              zone_id: 'z1',
              zone_name: 'Internal',
              targets: 2,
              status: 'started',
              run_id: 'r1',
              run_status: 'running',
            },
            { targets: 1, status: 'started', run_id: 'r2', run_status: 'completed' },
            {
              zone_id: 'z3',
              zone_name: 'Lab',
              targets: 4,
              status: 'refused',
              reason: 'window never opens',
            },
          ],
        }}
      />
    )
    expect(screen.getByText('Internal')).toBeInTheDocument()
    expect(screen.getByText('Outside every zone')).toBeInTheDocument()
    const links = screen.getAllByRole('link', { name: 'Open zone run' })
    expect(links.map((l) => l.getAttribute('href'))).toEqual([
      '/scans/runs?run=r1',
      '/scans/runs?run=r2',
    ])
    expect(screen.getByText(/Not started: window never opens/)).toBeInTheDocument()
  })

  it('links a zone run back to its parent', () => {
    render(
      <RunZoneSplitPanel split={{ zone_name: 'Internal', part: 1, parts: 3 }} parentRunId="p1" />
    )
    expect(screen.getByTestId('run-zone-split-child')).toHaveTextContent(
      'Zone run 1 of 3 (Internal)'
    )
    expect(screen.getByRole('link', { name: 'Open the scan run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=p1'
    )
  })
})
