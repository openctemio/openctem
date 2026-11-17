import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '@/context/i18n-provider'
import { FormDialog } from '../form-dialog'
import { FormField, FormSection, FormStack } from '../form-layout'
import { useDiscardPrompt } from '../leave-guard'

describe('FormField', () => {
  it('ties the label, the help and the error to its control', () => {
    render(
      <FormField label="Name" hint="Shown in lists." error="Give it a name.">
        <input />
      </FormField>
    )
    const input = screen.getByLabelText(/Name/)
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAttribute('aria-required', 'true')
    expect(input).toHaveAccessibleDescription('Give it a name. Shown in lists.')
    expect(screen.getByRole('alert')).toHaveTextContent('Give it a name.')
  })

  it('is required by default and says "Optional" when it is not', () => {
    render(
      <FormField label="Description" optional>
        <textarea />
      </FormField>
    )
    const field = screen.getByRole('textbox')
    expect(field).not.toHaveAttribute('aria-required')
    expect(field).not.toHaveAttribute('aria-invalid')
    expect(screen.getByText('Optional')).toBeInTheDocument()
  })

  it('can be not required without the mark (a preset choice)', () => {
    render(
      <FormField label="Targets per job" required={false}>
        <input defaultValue="10" />
      </FormField>
    )
    expect(screen.getByLabelText('Targets per job')).not.toHaveAttribute('aria-required')
    expect(screen.queryByText('Optional')).not.toBeInTheDocument()
  })

  it('says "Optional" in Vietnamese for the vi locale', () => {
    render(
      <I18nProvider locale="vi">
        <FormField label="Mô tả" optional>
          <textarea />
        </FormField>
      </I18nProvider>
    )
    expect(screen.getByText('Không bắt buộc')).toBeInTheDocument()
  })

  it('keeps a description the control already has and accepts a render function', () => {
    render(
      <>
        <p id="extra">Extra.</p>
        <FormField label="Day" hint="Of the month.">
          <input aria-describedby="extra" />
        </FormField>
        <FormField label="Time" warning="Outside the scan window.">
          {(control) => (
            <div>
              <input {...control} />
            </div>
          )}
        </FormField>
      </>
    )
    expect(screen.getByLabelText(/Day/)).toHaveAccessibleDescription('Extra. Of the month.')
    expect(screen.getByLabelText(/Time/)).toHaveAccessibleDescription('Outside the scan window.')
  })

  it('never clears an invalid mark the control set itself', () => {
    render(
      <FormField label="Date" optional>
        <input aria-invalid />
      </FormField>
    )
    expect(screen.getByLabelText(/Date/)).toHaveAttribute('aria-invalid', 'true')
  })

  it('renders a group as a fieldset named by its legend, with the error tied to it', () => {
    render(
      <FormField group label="What to run" error="Choose one.">
        <div>
          <input type="radio" name="what" aria-label="Single check" />
        </div>
      </FormField>
    )
    const group = screen.getByRole('group', { name: /What to run/ })
    expect(group).toHaveAccessibleDescription('Choose one.')
    expect(group).toHaveAttribute('aria-invalid', 'true')
  })
})

describe('FormSection', () => {
  it('is a region named by its title', () => {
    render(
      <FormStack>
        <FormSection title="Advanced" description="Job size and retries.">
          <p>fields</p>
        </FormSection>
      </FormStack>
    )
    expect(screen.getByRole('region', { name: 'Advanced' })).toHaveTextContent('fields')
  })
})

function Dialog({
  onSubmit = vi.fn(),
  canSubmit = true,
  error,
}: {
  onSubmit?: () => void
  canSubmit?: boolean
  error?: string
}) {
  const [open, setOpen] = useState(true)
  const [name, setName] = useState('')
  return (
    <FormDialog
      open={open}
      onOpenChange={setOpen}
      title="Create group"
      description="A named set of assets."
      submitLabel="Create"
      onSubmit={onSubmit}
      canSubmit={canSubmit}
      reason="Give the group a name."
      error={error}
      dirty={name !== ''}
    >
      <FormStack>
        <FormField label="Name">
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </FormField>
      </FormStack>
    </FormDialog>
  )
}

describe('FormDialog', () => {
  it('has a title, Cancel and one primary action; Enter in a field submits', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<Dialog onSubmit={onSubmit} />)
    const dialog = screen.getByRole('dialog', { name: 'Create group' })
    expect(dialog).toHaveAccessibleDescription('A named set of assets.')
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    await user.type(screen.getByLabelText(/Name/), 'Web{Enter}')
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('does not submit while it cannot, and says why with the button', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<Dialog onSubmit={onSubmit} canSubmit={false} />)
    const submit = screen.getByTestId('form-dialog-submit')
    expect(submit).toBeDisabled()
    expect(submit).toHaveAccessibleDescription('Give the group a name.')
    await user.type(screen.getByLabelText(/Name/), 'Web{Enter}')
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('announces a failed submit above the actions', () => {
    render(<Dialog error="The name is taken." />)
    expect(screen.getByRole('alert')).toHaveTextContent('The name is taken.')
  })

  it('asks before closing with unsaved changes, and closes at once without any', async () => {
    const user = userEvent.setup()
    render(<Dialog />)
    await user.type(screen.getByLabelText(/Name/), 'Web')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByRole('alertdialog', { name: 'Discard your changes?' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Keep editing' }))
    expect(screen.getByRole('dialog', { name: 'Create group' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await user.click(screen.getByRole('button', { name: 'Discard' }))
    expect(screen.queryByRole('dialog', { name: 'Create group' })).not.toBeInTheDocument()
  })
})

function Prompt({ close, keep }: { close: () => void; keep?: () => void }) {
  const { requestClose, prompt } = useDiscardPrompt(() => true, close, { keep })
  return (
    <>
      <button type="button" onClick={requestClose}>
        close
      </button>
      {prompt}
    </>
  )
}

describe('useDiscardPrompt', () => {
  it('offers Keep as draft when the form keeps one', async () => {
    const user = userEvent.setup()
    const close = vi.fn()
    const keep = vi.fn()
    render(<Prompt close={close} keep={keep} />)
    await user.click(screen.getByRole('button', { name: 'close' }))
    expect(
      screen.getByRole('alertdialog', { name: 'Close without finishing?' })
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Keep as draft' }))
    expect(keep).toHaveBeenCalledTimes(1)
    expect(close).not.toHaveBeenCalled()
  })
})
