import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { RunStatusBadge } from '@/features/shared'
import { LastRunCell } from '../last-run-cell'

describe('LastRunCell', () => {
  it('reads "Never" for a scan that never ran', () => {
    render(<LastRunCell run={null} />)
    expect(screen.getByText('Never')).toBeInTheDocument()
  })

  it('shows a live run with its progress', () => {
    render(
      <LastRunCell
        run={{ id: 'r1', status: 'running', created_at: new Date().toISOString(), progress: 42 }}
      />
    )
    expect(screen.getByText('Running')).toBeInTheDocument()
    expect(screen.getByText('42%')).toBeInTheDocument()
  })

  it('shows a blocked run with the reason on hover', () => {
    render(
      <LastRunCell
        run={{
          id: 'r2',
          status: 'blocked',
          created_at: new Date().toISOString(),
          refusal_code: 'ALL_TARGETS_EXCLUDED',
          error_message: 'Every target of scan "x" is excluded by scope',
        }}
      />
    )
    const chip = screen.getByText('Blocked').closest('[title]')
    expect(chip?.getAttribute('title')).toContain('Every target is excluded by scope')
  })

  it('opens the run when clicked', () => {
    const onOpen = vi.fn()
    render(
      <LastRunCell
        run={{ id: 'r3', status: 'completed', created_at: new Date().toISOString() }}
        onOpen={onOpen}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: /open the latest run/i }))
    expect(onOpen).toHaveBeenCalledWith('r3')
  })
})

describe('RunStatusBadge', () => {
  it('shows progress only for a live run', () => {
    const { rerender } = render(<RunStatusBadge status="completed" progress={42} />)
    expect(screen.queryByText('42%')).not.toBeInTheDocument()
    rerender(<RunStatusBadge status="running" progress={142} />)
    expect(screen.getByText('100%')).toBeInTheDocument()
  })

  it('knows the blocked state', () => {
    render(<RunStatusBadge status="blocked" />)
    expect(screen.getByText('Blocked')).toBeInTheDocument()
  })
})
