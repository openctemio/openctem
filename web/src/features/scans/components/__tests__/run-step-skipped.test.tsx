import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('@/lib/api/client', () => ({ get: vi.fn() }))

import { RunStepPanel } from '../run-step-panel'

function skipped(reason: string, skipReason: string) {
  return {
    step_key: 's',
    name: 'Screenshots',
    state: 'skipped',
    reason,
    error_class: 'config',
    skip_reason: skipReason,
    depends_on: [],
    findings: 0,
  } as never
}

// A step nothing here runs is skipped (the run goes on and ends partial):
// the panel explains the code with its fix and shows why it was skipped.
describe('RunStepPanel for a skipped step', () => {
  it('explains a step whose tool is not installed and shows the reason', () => {
    render(
      <RunStepPanel
        runId="r1"
        onClose={() => {}}
        node={skipped(
          'TOOL_NOT_INSTALLED',
          'skipped: tool checkov is not installed in this organization'
        )}
      />
    )
    expect(
      screen.getByText("Skipped: the step's tool is not installed in this organization.")
    ).toBeInTheDocument()
    expect(screen.getByText('Why it was skipped')).toBeInTheDocument()
    expect(
      screen.getByText('skipped: tool checkov is not installed in this organization')
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open scanning tools' })).toHaveAttribute(
      'href',
      '/settings/scanning/tools'
    )
  })

  it('explains a step whose needed step was skipped', () => {
    render(
      <RunStepPanel
        runId="r1"
        onClose={() => {}}
        node={skipped(
          'DEPENDENCY_SKIPPED',
          'skipped: it needs the results of step "iac", which was skipped'
        )}
      />
    )
    expect(
      screen.getByText('Skipped: a step this one needs the results of was skipped.')
    ).toBeInTheDocument()
    expect(screen.getByText(/needs the results of step "iac"/)).toBeInTheDocument()
  })

  it('shows no skip reason on a step that ran', () => {
    render(
      <RunStepPanel
        runId="r1"
        onClose={() => {}}
        node={
          {
            step_key: 's',
            state: 'succeeded',
            skip_reason: 'x',
            depends_on: [],
            findings: 0,
          } as never
        }
      />
    )
    expect(screen.queryByText('Why it was skipped')).toBeNull()
  })
})
