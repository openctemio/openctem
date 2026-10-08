import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { DraftIssuesPanel } from '../draft-issues-panel'
import type { ScanWorkflowStep } from '@/lib/api'

const steps = [
  { id: 's1', step_key: 'shots', name: 'Screenshots' },
  { id: 's2', step_key: 'dns', name: 'DNS' },
] as ScanWorkflowStep[]

describe('DraftIssuesPanel', () => {
  it('lists blocking issues and warnings with their fixes; choosing one selects its step', async () => {
    const onSelect = vi.fn()
    render(
      <DraftIssuesPanel
        steps={steps}
        onSelectStep={onSelect}
        report={{
          valid: false,
          errors: [
            {
              code: 'INVALID_TOOL',
              node: 'shots',
              message: 'step "Screenshots": tool "gowitness" is not installed in this organization',
              fix: 'Pick "Any tool" for the step, or add the tool to the organization.',
            },
          ],
          warnings: [
            {
              code: 'NO_SENSOR_FOR_CAPABILITY',
              node: 'dns',
              message: 'step "DNS": no online sensor offers DNS resolution (resolve.dns)',
            },
          ],
        }}
      />
    )
    expect(screen.getByText('1 blocking issue, 1 warning')).toBeInTheDocument()
    expect(screen.getByText(/fix the blocking issues to publish/)).toBeInTheDocument()
    expect(screen.getByText(/Pick "Any tool"/)).toBeInTheDocument()
    await userEvent.click(screen.getByText(/tool "gowitness" is not installed/))
    expect(onSelect).toHaveBeenCalledWith('shots')
  })

  it('shows nothing for a clean draft', () => {
    const { container } = render(
      <DraftIssuesPanel
        steps={steps}
        onSelectStep={vi.fn()}
        report={{ valid: true, errors: [], warnings: [] }}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
