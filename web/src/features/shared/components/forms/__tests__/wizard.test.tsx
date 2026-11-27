import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '@/context/i18n-provider'
import { WizardFrame, WizardSteps, useWizardSteps, type WizardStepStatus } from '../wizard'

type Step = 'one' | 'two' | 'three'
const STEPS: { id: Step; label: string }[] = [
  { id: 'one', label: 'First' },
  { id: 'two', label: 'Second' },
  { id: 'three', label: 'Third' },
]

describe('WizardSteps', () => {
  it('lets every step be opened, later ones too (free navigation)', async () => {
    const user = userEvent.setup()
    const onStepChange = vi.fn()
    render(<WizardSteps steps={STEPS} current="one" onStepChange={onStepChange} />)
    const buttons = within(screen.getByRole('navigation', { name: 'Steps' })).getAllByRole('button')
    expect(buttons).toHaveLength(3)
    expect(buttons.every((b) => !(b as HTMLButtonElement).disabled)).toBe(true)
    await user.click(buttons[2])
    expect(onStepChange).toHaveBeenCalledWith('three')
  })

  it('says each step state in its accessible name and marks the current step', () => {
    const status: Partial<Record<Step, WizardStepStatus>> = {
      one: { state: 'valid', count: 0 },
      two: { state: 'invalid', count: 2 },
    }
    render(<WizardSteps steps={STEPS} current="two" status={status} />)
    expect(screen.getByRole('button', { name: 'First, complete' })).toBeInTheDocument()
    const second = screen.getByRole('button', { name: 'Second, 2 problems' })
    expect(second).toHaveAttribute('aria-current', 'step')
    expect(second).toHaveAttribute('data-status', 'invalid')
    expect(screen.getByRole('button', { name: 'Third' })).not.toHaveAttribute('aria-current')
  })

  it('keeps one mark box per step whatever its state, so the strip never moves', () => {
    const { rerender } = render(<WizardSteps steps={STEPS} current="one" />)
    const boxes = () =>
      Array.from(document.querySelectorAll('[data-slot="wizard-steps"] button > span:first-child'))
    const before = boxes().map((b) => b.className.split(' ').filter((c) => c.startsWith('size-')))
    rerender(
      <WizardSteps
        steps={STEPS}
        current="one"
        status={{ one: { state: 'valid', count: 0 }, two: { state: 'invalid', count: 12 } }}
      />
    )
    const after = boxes().map((b) => b.className.split(' ').filter((c) => c.startsWith('size-')))
    expect(after).toEqual(before)
    expect(before.every((c) => c.length === 1 && c[0] === 'size-5')).toBe(true)
  })

  it('labels the strip in Vietnamese for the vi locale', () => {
    render(
      <I18nProvider locale="vi">
        <WizardSteps steps={STEPS} current="one" status={{ one: { state: 'valid', count: 0 } }} />
      </I18nProvider>
    )
    expect(screen.getByRole('navigation', { name: 'Các bước' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'First, đã xong' })).toBeInTheDocument()
  })
})

function Frame({
  problem = null,
  onSubmit = vi.fn(),
  onRequestClose = vi.fn(),
  isLoading = false,
}: {
  problem?: { step: Step; message: string } | null
  onSubmit?: () => void
  onRequestClose?: () => void
  isLoading?: boolean
}) {
  const nav = useWizardSteps<Step>('one')
  return (
    <WizardFrame
      open
      onRequestClose={onRequestClose}
      title="New thing"
      description="What it is for"
      steps={STEPS}
      step={nav.step}
      onStepChange={nav.setStep}
      problem={problem}
      canSubmit={!problem}
      onSubmit={onSubmit}
      isLoading={isLoading}
      summary={{ title: 'Summary', line: 'one line', content: <p>whole summary</p> }}
      primary={
        <button type="button" disabled={!!problem} onClick={onSubmit}>
          Create
        </button>
      }
    >
      {nav.step === 'two' ? (
        <input aria-label="Second field" aria-invalid={problem ? true : undefined} />
      ) : (
        <p>Body of {nav.step}</p>
      )}
    </WizardFrame>
  )
}

describe('WizardFrame', () => {
  it('shows Back from the second step, Next until the last, the primary action on the last', async () => {
    const user = userEvent.setup()
    render(<Frame />)
    expect(screen.queryByTestId('wizard-back')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create' })).not.toBeInTheDocument()
    await user.click(screen.getByTestId('wizard-next'))
    expect(screen.getByTestId('wizard-back')).toBeInTheDocument()
    await user.click(screen.getByTestId('wizard-next'))
    expect(screen.queryByTestId('wizard-next')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create' })).toBeEnabled()
  })

  it('announces the step through its heading, which takes focus on a step change', async () => {
    const user = userEvent.setup()
    render(<Frame />)
    await user.click(screen.getByTestId('wizard-next'))
    const heading = screen.getByTestId('wizard-step-heading')
    expect(heading).toHaveTextContent('Step 2 of 3: Second')
    await vi.waitFor(() => expect(heading).toHaveFocus())
  })

  it('names the first problem in the footer and takes the person to its field', async () => {
    const user = userEvent.setup()
    render(<Frame problem={{ step: 'two', message: 'Fill the second field' }} />)
    await user.click(screen.getByRole('button', { name: 'Third' }))
    expect(screen.getByTestId('wizard-note')).toHaveTextContent('Fill the second field')
    expect(screen.getByTestId('wizard-fix-link')).toHaveTextContent('Go to Second')
    // The note takes the summary line's place: the footer keeps one line.
    expect(screen.queryByTestId('summary-bar')).not.toBeInTheDocument()
    await user.click(screen.getByTestId('wizard-fix-link'))
    await vi.waitFor(() => expect(screen.getByLabelText('Second field')).toHaveFocus())
  })

  it('Ctrl+Enter submits when it can and goes to the problem when it cannot', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    const { unmount } = render(<Frame onSubmit={onSubmit} />)
    screen.getByText('Body of one').focus()
    await user.keyboard('{Control>}{Enter}{/Control}')
    expect(onSubmit).toHaveBeenCalledTimes(1)
    unmount()
    render(<Frame onSubmit={onSubmit} problem={{ step: 'two', message: 'Fill it' }} />)
    await user.keyboard('{Meta>}{Enter}{/Meta}')
    expect(onSubmit).toHaveBeenCalledTimes(1)
    await vi.waitFor(() => expect(screen.getByLabelText('Second field')).toHaveFocus())
  })

  it('does not close while saving', async () => {
    const user = userEvent.setup()
    const onRequestClose = vi.fn()
    const { rerender } = render(<Frame onRequestClose={onRequestClose} isLoading />)
    await user.keyboard('{Escape}')
    expect(onRequestClose).not.toHaveBeenCalled()
    rerender(<Frame onRequestClose={onRequestClose} />)
    await user.keyboard('{Escape}')
    expect(onRequestClose).toHaveBeenCalledTimes(1)
  })

  it('opens the whole summary from its line in the footer', async () => {
    const user = userEvent.setup()
    render(<Frame />)
    const line = screen.getByTestId('summary-bar')
    expect(line).toHaveTextContent('one line')
    await user.click(line)
    expect(screen.getByRole('region', { name: 'Summary' })).toHaveTextContent('whole summary')
    await user.click(line)
    expect(screen.queryByText('whole summary')).not.toBeInTheDocument()
  })
})
