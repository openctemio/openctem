import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('@/lib/api/client', () => ({ get: vi.fn() }))

import { RunStatusBadge } from '@/features/shared'
import { runResultHelp } from '../../lib/run-display'
import { RunStepPanel } from '../run-step-panel'

function node(over: Record<string, unknown>) {
  return { step_key: 'retest', name: 'Retest', depends_on: [], findings: 0, ...over } as never
}

describe('RunStatusBadge with a result', () => {
  it('reads a completed, inconclusive run as amber and never Failed', () => {
    const { container } = render(
      <RunStatusBadge
        status="completed"
        result={{ kind: 'inconclusive', code: 'endpoint_mismatch' }}
      />
    )
    expect(screen.getByText('Completed, inconclusive')).toBeInTheDocument()
    expect(screen.queryByText('Failed')).toBeNull()
    expect(
      container.querySelector('[data-slot="health-status"]')?.getAttribute('data-health')
    ).toBe('warn')
  })

  it('reads an exposure at another path as amber', () => {
    const { container } = render(
      <RunStatusBadge status="completed" result={{ kind: 'still_exposed_elsewhere' }} />
    )
    expect(screen.getByText('Completed, exposed at another path')).toBeInTheDocument()
    expect(
      container.querySelector('[data-slot="health-status"]')?.getAttribute('data-health')
    ).toBe('warn')
  })

  it('a plain completed run stays Completed, and a result never softens a failed run', () => {
    const { rerender } = render(<RunStatusBadge status="completed" />)
    expect(screen.getByText('Completed')).toBeInTheDocument()
    rerender(<RunStatusBadge status="failed" result={{ kind: 'inconclusive' }} />)
    expect(screen.getByText('Failed')).toBeInTheDocument()
  })
})

describe('runResultHelp', () => {
  it('has wording for every code, never the raw code', () => {
    for (const code of [
      'endpoint_mismatch',
      'blocked',
      'auth_changed',
      'matched_elsewhere',
      'made_up',
    ]) {
      const h = runResultHelp({ kind: 'inconclusive', code })
      expect(h.text).not.toMatch(/scans\.result/)
      expect(h.fix).not.toMatch(/scans\.result/)
    }
  })
})

describe('RunStepPanel with a result', () => {
  it('explains an inconclusive step in words, without the Tool chip or the code', () => {
    render(
      <RunStepPanel
        runId="r1"
        runKind="retest"
        onClose={() => {}}
        node={node({
          state: 'succeeded',
          result: { kind: 'inconclusive', code: 'endpoint_mismatch' },
        })}
      />
    )
    expect(screen.getByText('Inconclusive result')).toBeInTheDocument()
    expect(
      screen.getByText(/did not request this finding's own endpoint, so it proves nothing/)
    ).toBeInTheDocument()
    expect(screen.getByText(/pinned to the exact URL/)).toBeInTheDocument()
    expect(screen.queryByText('endpoint_mismatch')).toBeNull()
    expect(screen.queryByText('Tool')).toBeNull()
    expect(
      screen.getByText('A retest produces a verdict, not assets. See the result above.')
    ).toBeInTheDocument()
  })

  it('a real failure keeps its code chip and class chip', () => {
    render(
      <RunStepPanel
        runId="r1"
        onClose={() => {}}
        node={node({
          state: 'failed',
          reason: 'TOOL_EXIT',
          error_class: 'tool',
          error_message: 'x',
        })}
      />
    )
    expect(screen.getByText('TOOL_EXIT')).toBeInTheDocument()
    expect(screen.getByText('Tool')).toBeInTheDocument()
  })

  it('an ordinary step with no output says it produced no assets, in sentence case headings', () => {
    const { container } = render(
      <RunStepPanel runId="r1" onClose={() => {}} node={node({ state: 'succeeded' })} />
    )
    expect(screen.getByText('This step produced no assets.')).toBeInTheDocument()
    expect(screen.queryByText(/Nothing produced yet/)).toBeNull()
    expect(container.querySelector('h5.uppercase')).toBeNull()
    expect(screen.getByText('Outputs')).toBeInTheDocument()
  })
})
