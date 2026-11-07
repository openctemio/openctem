import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../../types'
import { ScanSummaryContent } from '../scan-summary'
import type { StepIssues } from '../../../lib/wizard-validity'

const NONE: StepIssues = { basic: [], targets: [], options: [], schedule: [], review: [] }
const STEPS = ['basic', 'targets', 'options', 'schedule', 'review'] as const

const form: NewScanFormData = {
  ...DEFAULT_NEW_SCAN,
  name: 'Deep recon weekly',
  mode: 'workflow',
  workflowId: 'w1',
  intensity: 'intrusive',
  maxConcurrent: 10,
  targets: {
    ...DEFAULT_NEW_SCAN.targets,
    customTargets: ['a.example.com'],
    assetGroupIds: ['g1'],
  },
}

function renderSummary(patch: Partial<Parameters<typeof ScanSummaryContent>[0]> = {}) {
  return render(
    <ScanSummaryContent
      data={form}
      whatLabel="Deep recon"
      directCount={245}
      ready={241}
      blocked={4}
      issues={NONE}
      steps={[...STEPS]}
      shownSteps={new Set()}
      onGo={vi.fn()}
      {...patch}
    />
  )
}

describe('ScanSummaryContent', () => {
  it('says what runs, the intensity in plain words, targets with groups, and the jobs', () => {
    renderSummary()
    const summary = screen.getByTestId('scan-summary')
    expect(summary).toHaveTextContent('Deep recon weekly')
    expect(summary).toHaveTextContent('Intrusive')
    expect(summary).toHaveTextContent('May send attack payloads')
    expect(screen.getByTestId('summary-targets')).toHaveTextContent(
      '245 targets and 1 asset group (members added at run time)'
    )
    expect(summary).toHaveTextContent('241 ready, 4 blocked')
    expect(summary).toHaveTextContent(
      '25 jobs per run (10 targets per job), more for group members'
    )
  })

  it('says who must approve before Review', () => {
    renderSummary({
      approval: { mode: 'on', required: true, approvals: 2, approver_roles: ['security lead'] },
    })
    expect(screen.getByTestId('summary-approval')).toHaveTextContent(
      'Needs 2 approvals before it runs, by: security lead'
    )
  })

  it('lists each workflow step: the tool it runs with, or why it is skipped; how many run', () => {
    renderSummary({
      workflowReadiness: {
        state: 'ready',
        steps: [
          { step_key: 'subs', name: 'Subdomains', state: 'ready', tool: 'subfinder' },
          {
            step_key: 'shots',
            name: 'Screenshots',
            state: 'skipped',
            optional: true,
            capability: 'capture.screenshot',
          },
          {
            step_key: 'svc',
            name: 'Services',
            state: 'blocked',
            code: 'no_tool',
            capability: 'detect.services',
            reason: 'No tool runs detect.services',
          },
        ],
      },
    })
    expect(screen.getByTestId('summary-steps-count')).toHaveTextContent('1 of 3 steps will run')
    const steps = screen.getByTestId('summary-steps')
    const row = (name: string) => within(steps).getByText(name).closest('li') as HTMLElement
    expect(row('Subdomains')).toHaveTextContent('Runs with subfinder')
    expect(row('Screenshots')).toHaveTextContent('Skipped: no tool provides capture.screenshot yet')
    expect(row('Services')).toHaveTextContent('Skipped for now')
  })

  it('links each shown problem to its step', async () => {
    const user = userEvent.setup()
    const onGo = vi.fn()
    renderSummary({
      issues: { ...NONE, targets: ['Add at least one target'] },
      shownSteps: new Set(['targets']),
      onGo,
    })
    await user.click(screen.getByTestId('summary-problem'))
    expect(onGo).toHaveBeenCalledWith('targets')
  })

  it('shows no problem of a step not visited yet', () => {
    renderSummary({ issues: { ...NONE, targets: ['Add at least one target'] } })
    expect(screen.queryByTestId('summary-problem')).not.toBeInTheDocument()
  })
})
