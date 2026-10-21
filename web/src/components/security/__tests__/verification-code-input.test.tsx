import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  VerificationCodeInput,
  formatCodeGroups,
  normalizeVerificationCode,
  type VerificationCodeInputProps,
} from '../verification-code-input'

function Harness(props: Partial<VerificationCodeInputProps> & { onCode?: (code: string) => void }) {
  const [value, setValue] = useState('')
  return (
    <VerificationCodeInput
      {...props}
      label={props.label ?? 'Code from your authenticator app'}
      value={value}
      onChange={(c) => {
        setValue(c)
        props.onCode?.(c)
      }}
    />
  )
}

describe('normalizeVerificationCode', () => {
  it('drops separators and keeps digits only in numeric mode', () => {
    expect(normalizeVerificationCode('123 456')).toBe('123456')
    expect(normalizeVerificationCode('123-456')).toBe('123456')
    expect(normalizeVerificationCode(' 12a3b4 56 ')).toBe('123456')
  })

  it('turns full-width and Arabic-Indic digits into ASCII', () => {
    expect(normalizeVerificationCode('１２３４５６')).toBe('123456')
    expect(normalizeVerificationCode('١٢٣٤٥٦')).toBe('123456')
    expect(normalizeVerificationCode('۱۲۳۴۵۶')).toBe('123456')
  })

  it('cuts to the length', () => {
    expect(normalizeVerificationCode('12345678')).toBe('123456')
    expect(normalizeVerificationCode('abcde-fghjk-x', 'alphanumeric', 10)).toBe('abcdefghjk')
  })

  it('keeps letters in alphanumeric mode and drops other characters', () => {
    expect(normalizeVerificationCode('ab cd-ef ăê', 'alphanumeric', 10)).toBe('abcdef')
  })
})

describe('formatCodeGroups', () => {
  it('prints the groups as the code is typed', () => {
    expect(formatCodeGroups('abc', [5, 5])).toBe('abc')
    expect(formatCodeGroups('abcde', [5, 5])).toBe('abcde')
    expect(formatCodeGroups('abcdef', [5, 5])).toBe('abcde-f')
    expect(formatCodeGroups('ABCD1234WXYZ', [4, 4, 4])).toBe('ABCD-1234-WXYZ')
  })
})

describe('VerificationCodeInput', () => {
  it('is one labelled text field with one-time-code autofill and a numeric keypad', () => {
    render(<Harness />)
    const input = screen.getByRole('textbox', { name: 'Code from your authenticator app' })
    expect(input).toHaveAttribute('autocomplete', 'one-time-code')
    expect(input).toHaveAttribute('inputmode', 'numeric')
    expect(input).toHaveAttribute('dir', 'ltr')
    expect(input).toHaveAccessibleDescription('Enter the 6-digit code.')
    // The cells are decoration only: one field for assistive technology.
    expect(screen.getAllByRole('textbox')).toHaveLength(1)
  })

  it('ignores letters while typing and shows each digit in a cell', async () => {
    const user = userEvent.setup()
    const { container } = render(<Harness />)
    const input = screen.getByRole('textbox')
    await user.type(input, '1a2b3')
    expect(input).toHaveValue('123')
    const cells = container.querySelectorAll('[data-slot="verification-code-cell"]')
    expect(cells).toHaveLength(6)
    expect(Array.from(cells, (c) => c.textContent)).toEqual(['1', '2', '3', '', '', ''])
  })

  it('pastes a whole code with spaces or dashes and completes once', async () => {
    const user = userEvent.setup()
    const onComplete = vi.fn()
    render(<Harness onComplete={onComplete} />)
    const input = screen.getByRole('textbox')
    await user.click(input)
    await user.paste('123 456')
    expect(input).toHaveValue('123456')
    expect(onComplete).toHaveBeenCalledTimes(1)
    expect(onComplete).toHaveBeenCalledWith('123456')

    await user.clear(input)
    await user.paste('654-321')
    expect(input).toHaveValue('654321')
    expect(onComplete).toHaveBeenCalledTimes(2)
    expect(onComplete).toHaveBeenLastCalledWith('654321')
  })

  it('accepts an autofilled code (one change event with the whole value)', () => {
    const onComplete = vi.fn()
    render(<Harness onComplete={onComplete} />)
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '987 654' } })
    expect(screen.getByRole('textbox')).toHaveValue('987654')
    expect(onComplete).toHaveBeenCalledWith('987654')
  })

  it('backspace removes the last digit across cells', async () => {
    const user = userEvent.setup()
    const onCode = vi.fn()
    render(<Harness onCode={onCode} />)
    const input = screen.getByRole('textbox')
    await user.type(input, '1234')
    await user.keyboard('{Backspace}{Backspace}')
    expect(input).toHaveValue('12')
    expect(onCode).toHaveBeenLastCalledWith('12')
  })

  it('does not complete again for extra keystrokes after the code is full', async () => {
    const user = userEvent.setup()
    const onComplete = vi.fn()
    render(<Harness onComplete={onComplete} />)
    const input = screen.getByRole('textbox')
    await user.type(input, '1234567')
    expect(input).toHaveValue('123456')
    expect(onComplete).toHaveBeenCalledTimes(1)
  })

  it('does not complete while disabled', () => {
    const onComplete = vi.fn()
    render(<Harness onComplete={onComplete} disabled />)
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '123456' } })
    expect(onComplete).not.toHaveBeenCalled()
    expect(screen.getByRole('textbox')).toBeDisabled()
  })

  it('waits for an IME composition to end before normalising', () => {
    const onCode = vi.fn()
    render(<Harness onCode={onCode} />)
    const input = screen.getByRole('textbox')
    fireEvent.compositionStart(input)
    fireEvent.change(input, { target: { value: '１２' } })
    expect(onCode).not.toHaveBeenCalled()
    fireEvent.compositionEnd(input, { target: { value: '１２' } })
    expect(onCode).toHaveBeenLastCalledWith('12')
  })

  it('shows an error in a live region, marks the field invalid and focuses it', () => {
    const { rerender } = render(
      <VerificationCodeInput label="Code" value="" onChange={() => {}} error={null} />
    )
    const input = screen.getByRole('textbox')
    expect(input).not.toHaveAttribute('aria-invalid')
    rerender(
      <VerificationCodeInput
        label="Code"
        value=""
        onChange={() => {}}
        error="That code is not valid."
      />
    )
    expect(screen.getByRole('alert')).toHaveTextContent('That code is not valid.')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAccessibleDescription(/That code is not valid\./)
    expect(input).toHaveFocus()
  })

  it('recovery codes: free text, grouped as printed, no one-time-code autofill', async () => {
    const user = userEvent.setup()
    const onComplete = vi.fn()
    render(
      <Harness
        label="Recovery code"
        mode="alphanumeric"
        length={10}
        groups={[5, 5]}
        onComplete={onComplete}
      />
    )
    const input = screen.getByRole('textbox', { name: 'Recovery code' })
    expect(input).toHaveAttribute('autocomplete', 'off')
    expect(input).toHaveAttribute('inputmode', 'text')
    await user.type(input, 'abcde-fgh')
    expect(input).toHaveValue('abcde-fgh')
    await user.type(input, 'jk')
    expect(onComplete).toHaveBeenCalledWith('abcdefghjk')
  })
})

describe('VerificationCodeInput accessible name', () => {
  it.each(['numeric', 'alphanumeric'] as const)('names the %s input from its label', (mode) => {
    render(<Harness label="Authentication code" mode={mode} />)
    expect(screen.getByRole('textbox', { name: 'Authentication code' })).toBeInTheDocument()
  })

  it('keeps the name when the label is visually hidden', () => {
    render(<Harness label="Authentication code" hideLabel />)
    expect(screen.getByLabelText('Authentication code')).toBeInTheDocument()
  })
})
