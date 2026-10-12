import { describe, it, expect, vi } from 'vitest'
import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TargetLinesInput, parseTargetLines } from '../target-lines-input'

function Harness({ onTargets }: { onTargets?: (t: string[]) => void }) {
  const [targets, setTargets] = useState<string[]>([])
  return (
    <>
      <TargetLinesInput
        aria-label="Targets"
        value={targets}
        onChange={(t) => {
          setTargets(t)
          onTargets?.(t)
        }}
      />
      <button type="button" onClick={() => setTargets((t) => [...t, 'example.com'])}>
        add example
      </button>
      <output data-testid="list">{targets.join('|')}</output>
    </>
  )
}

describe('TargetLinesInput', () => {
  it('keeps the newline typed after a target, so targets go on separate lines', async () => {
    const user = userEvent.setup()
    const onTargets = vi.fn()
    render(<Harness onTargets={onTargets} />)
    const box = screen.getByLabelText('Targets')
    await user.type(box, 'a.example.com{Enter}b.example.com')
    expect(box).toHaveValue('a.example.com\nb.example.com')
    expect(onTargets).toHaveBeenLastCalledWith(['a.example.com', 'b.example.com'])
  })

  it('reports trimmed non-empty lines but keeps blank lines as typed', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const box = screen.getByLabelText('Targets')
    await user.type(box, '  a.com {Enter}{Enter}b.com{Enter}')
    expect(box).toHaveValue('  a.com \n\nb.com\n')
    expect(screen.getByTestId('list')).toHaveTextContent('a.com|b.com')
  })

  it('shows a change made outside the input', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const box = screen.getByLabelText('Targets')
    await user.type(box, 'a.com')
    await user.click(screen.getByRole('button', { name: 'add example' }))
    expect(box).toHaveValue('a.com\nexample.com')
  })
})

describe('parseTargetLines', () => {
  it('trims and drops empty lines', () => {
    expect(parseTargetLines(' a \n\n b\n')).toEqual(['a', 'b'])
    expect(parseTargetLines('')).toEqual([])
  })
})
