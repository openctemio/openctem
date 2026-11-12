import { useState } from 'react'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { ScanWizard, useWizardSteps } from '../scan-wizard'
import type { ScanWizardStep } from '../scan-stepper'
import type { StepIssues } from '../../../lib/wizard-validity'

const STEPS: ScanWizardStep[] = ['basic', 'targets', 'options', 'schedule', 'review']
const NONE: StepIssues = { basic: [], targets: [], options: [], schedule: [], review: [] }

function Harness({
  issues = NONE,
  onSubmit = vi.fn(),
  submitOnEveryStep = false,
}: {
  issues?: StepIssues
  onSubmit?: () => void
  submitOnEveryStep?: boolean
}) {
  const nav = useWizardSteps('basic')
  const [name, setName] = useState('')
  const canSubmit = Object.values(issues).every((x) => x.length === 0)
  return (
    <ScanWizard
      open
      onRequestClose={vi.fn()}
      title="New scan"
      steps={STEPS}
      step={nav.step}
      onStepChange={nav.setStep}
      issues={issues}
      attempted={nav.attempted}
      seen={nav.seen}
      summary={<p>summary body</p>}
      summaryLine="2 targets, Run now, Active"
      canSubmit={canSubmit}
      onSubmit={onSubmit}
      submitOnEveryStep={submitOnEveryStep}
      primary={
        <button type="button" disabled={!canSubmit} onClick={onSubmit}>
          Create scan
        </button>
      }
    >
      <div data-testid="step-body">
        {nav.step === 'targets' ? (
          <input
            aria-label="Targets field"
            aria-invalid={issues.targets.length > 0 || undefined}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        ) : (
          <p>Body of {nav.step}</p>
        )}
      </div>
    </ScanWizard>
  )
}

function desktopStep(name: RegExp) {
  const nav = screen.getByRole('navigation', { name: 'Steps' })
  const desktop = nav.querySelector('ol.hidden') as HTMLElement
  return within(desktop).getByRole('button', { name })
}

describe('ScanWizard', () => {
  it('opens any step from the stepper, also before the earlier ones are complete', async () => {
    const user = userEvent.setup()
    render(
      <Harness
        issues={{ ...NONE, basic: ['Give the scan a name'], targets: ['Add at least one target'] }}
      />
    )
    expect(screen.getByText('Body of basic')).toBeInTheDocument()
    await user.click(desktopStep(/Schedule/))
    expect(screen.getByText('Body of schedule')).toBeInTheDocument()
    await user.click(desktopStep(/Review/))
    expect(screen.getByText('Body of review')).toBeInTheDocument()
  })

  it('Next moves on without stopping at a problem, and the step left then shows it', async () => {
    const user = userEvent.setup()
    render(<Harness issues={{ ...NONE, basic: ['Give the scan a name'] }} />)
    expect(desktopStep(/^What$/)).toBeInTheDocument()
    await user.click(screen.getByTestId('wizard-next'))
    expect(screen.getByLabelText('Targets field')).toBeInTheDocument()
    expect(desktopStep(/What, 1 problem/)).toBeInTheDocument()
  })

  it('keeps Create disabled until every step is valid and links the first problem to its step', async () => {
    const user = userEvent.setup()
    render(<Harness issues={{ ...NONE, targets: ['Add at least one target'] }} />)
    await user.click(desktopStep(/Review/))
    expect(screen.getByRole('button', { name: 'Create scan' })).toBeDisabled()
    expect(screen.getByTestId('wizard-note')).toHaveTextContent('Add at least one target')
    await user.click(screen.getByTestId('wizard-fix-link'))
    await vi.waitFor(() => expect(screen.getByLabelText('Targets field')).toHaveFocus())
  })

  it('Ctrl+Enter creates when every step is valid', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<Harness onSubmit={onSubmit} />)
    screen.getByText('Body of basic').focus()
    await user.keyboard('{Control>}{Enter}{/Control}')
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('Cmd+Enter with a problem goes to it instead of creating', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <Harness onSubmit={onSubmit} issues={{ ...NONE, targets: ['Add at least one target'] }} />
    )
    await user.keyboard('{Meta>}{Enter}{/Meta}')
    expect(onSubmit).not.toHaveBeenCalled()
    await vi.waitFor(() => expect(screen.getByLabelText('Targets field')).toHaveFocus())
  })

  it('moves focus to the step heading after a step change', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByTestId('wizard-next'))
    const heading = screen.getByTestId('wizard-step-heading')
    expect(heading).toHaveTextContent('Step 2 of 5: Targets')
    await vi.waitFor(() => expect(heading).toHaveFocus())
  })

  it('Back goes to the previous step; the first step has no Back', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    expect(screen.queryByTestId('wizard-back')).not.toBeInTheDocument()
    await user.click(screen.getByTestId('wizard-next'))
    await user.click(screen.getByTestId('wizard-back'))
    expect(screen.getByText('Body of basic')).toBeInTheDocument()
  })

  it('offers the primary action on every step when asked (Edit)', () => {
    render(<Harness submitOnEveryStep />)
    expect(screen.getByRole('button', { name: 'Create scan' })).toBeEnabled()
    expect(screen.getByTestId('wizard-next')).toBeInTheDocument()
  })

  it('shows the summary beside the step and in the phone bar', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const bar = screen.getByTestId('summary-bar')
    expect(bar).toHaveTextContent('2 targets, Run now, Active')
    await user.click(within(bar).getByRole('button'))
    expect(within(bar).getByText('summary body')).toBeInTheDocument()
    expect(screen.getByRole('complementary', { name: 'Summary' })).toHaveTextContent('summary body')
  })
})
