import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { splitTargetInput, TargetChipsField, type TargetChip } from '../target-chips-field'

const chip = (label: string, onRemove?: () => void): TargetChip => ({
  key: label,
  label,
  kind: 'typed',
  onRemove,
})

describe('splitTargetInput', () => {
  it('splits on spaces, commas, semicolons and new lines', () => {
    expect(splitTargetInput('a.example, b.example\nc.example;  d.example ')).toEqual([
      'a.example',
      'b.example',
      'c.example',
      'd.example',
    ])
  })
})

describe('TargetChipsField', () => {
  it('adds a typed target on Enter and on a comma', async () => {
    const user = userEvent.setup()
    const onAdd = vi.fn()
    render(<TargetChipsField id="f" chips={[]} onAdd={onAdd} />)
    const input = screen.getByRole('textbox')
    await user.type(input, 'a.example{Enter}')
    expect(onAdd).toHaveBeenLastCalledWith(['a.example'])
    await user.type(input, 'b.example,')
    expect(onAdd).toHaveBeenLastCalledWith(['b.example'])
    expect(input).toHaveValue('')
  })

  it('adds every target of a pasted list at once', () => {
    const onAdd = vi.fn()
    render(<TargetChipsField id="f" chips={[]} onAdd={onAdd} />)
    fireEvent.paste(screen.getByRole('textbox'), {
      clipboardData: { getData: () => 'a.example\nb.example\n10.0.0.0/24' },
    })
    expect(onAdd).toHaveBeenCalledWith(['a.example', 'b.example', '10.0.0.0/24'])
  })

  it('removes the last typed target on Backspace in an empty input', async () => {
    const user = userEvent.setup()
    const onRemoveLast = vi.fn()
    render(
      <TargetChipsField
        id="f"
        chips={[chip('a.example')]}
        onAdd={vi.fn()}
        onRemoveLast={onRemoveLast}
      />
    )
    await user.type(screen.getByRole('textbox'), '{Backspace}')
    expect(onRemoveLast).toHaveBeenCalledTimes(1)
  })

  it('gives each chip a remove button with a 44 px tap area', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    render(<TargetChipsField id="f" chips={[chip('a.example', onRemove)]} onAdd={vi.fn()} />)
    const remove = screen.getByRole('button', { name: 'Remove a.example' })
    // 32 px button plus a 6 px hit extension on every side.
    expect(remove.className).toContain('h-8 w-8')
    expect(remove.className).toContain('after:-inset-1.5')
    await user.click(remove)
    expect(onRemove).toHaveBeenCalledTimes(1)
  })
})
