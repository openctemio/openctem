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

  describe('editing a typed chip', () => {
    const editable = (label: string, onEdit: (n: string) => void): TargetChip => ({
      key: label,
      label,
      kind: 'typed',
      onEdit,
    })

    it('turns the chip into an input on click, Enter and F2, and commits on Enter', async () => {
      const user = userEvent.setup()
      const onEdit = vi.fn()
      render(<TargetChipsField id="f" chips={[editable('a.exmaple', onEdit)]} onAdd={vi.fn()} />)
      await user.click(screen.getByRole('button', { name: 'Edit a.exmaple' }))
      const input = screen.getByTestId('target-chip-edit')
      expect(input).toHaveValue('a.exmaple')
      await user.clear(input)
      await user.type(input, 'a.example{Enter}')
      expect(onEdit).toHaveBeenCalledExactlyOnceWith('a.example')
      expect(screen.queryByTestId('target-chip-edit')).not.toBeInTheDocument()

      screen.getByRole('button', { name: 'Edit a.exmaple' }).focus()
      await user.keyboard('{Enter}')
      expect(screen.getByTestId('target-chip-edit')).toBeInTheDocument()
      await user.keyboard('{Escape}')
      screen.getByRole('button', { name: 'Edit a.exmaple' }).focus()
      await user.keyboard('{F2}')
      expect(screen.getByTestId('target-chip-edit')).toBeInTheDocument()
    })

    it('commits on blur', async () => {
      const user = userEvent.setup()
      const onEdit = vi.fn()
      render(<TargetChipsField id="f" chips={[editable('a.exmaple', onEdit)]} onAdd={vi.fn()} />)
      await user.click(screen.getByRole('button', { name: 'Edit a.exmaple' }))
      await user.type(screen.getByTestId('target-chip-edit'), '2')
      await user.tab()
      expect(onEdit).toHaveBeenCalledExactlyOnceWith('a.exmaple2')
    })

    it('cancels on Escape without changing the chip', async () => {
      const user = userEvent.setup()
      const onEdit = vi.fn()
      render(<TargetChipsField id="f" chips={[editable('a.example', onEdit)]} onAdd={vi.fn()} />)
      await user.click(screen.getByRole('button', { name: 'Edit a.example' }))
      await user.type(screen.getByTestId('target-chip-edit'), 'zzz{Escape}')
      expect(onEdit).not.toHaveBeenCalled()
      expect(screen.getByRole('button', { name: 'Edit a.example' })).toBeInTheDocument()
    })

    it('hands an empty commit to the parent, which removes the chip', async () => {
      const user = userEvent.setup()
      const onEdit = vi.fn()
      render(<TargetChipsField id="f" chips={[editable('a.example', onEdit)]} onAdd={vi.fn()} />)
      await user.click(screen.getByRole('button', { name: 'Edit a.example' }))
      await user.clear(screen.getByTestId('target-chip-edit'))
      await user.keyboard('{Enter}')
      expect(onEdit).toHaveBeenCalledExactlyOnceWith('')
    })

    it('does not make asset or group chips editable', () => {
      render(
        <TargetChipsField
          id="f"
          chips={[
            { key: 'a', label: 'web-1', kind: 'asset', onRemove: vi.fn() },
            { key: 'g', label: 'prod', kind: 'group', onRemove: vi.fn() },
          ]}
          onAdd={vi.fn()}
        />
      )
      expect(screen.queryByRole('button', { name: /^Edit / })).not.toBeInTheDocument()
    })
  })
})
