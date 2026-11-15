import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingsBaseChips } from '../base-chips'

const counts = {
  byPractice: { aspm: 4, infra: 0, compliance: 2, external: 1 },
  vulnerabilities: 5,
  total: 7,
}

function setup(over: Partial<React.ComponentProps<typeof FindingsBaseChips>> = {}) {
  const onPracticeChange = vi.fn()
  const onLensChange = vi.fn()
  render(
    <FindingsBaseChips
      practice="vulnerabilities"
      practiceCounts={counts}
      onPracticeChange={onPracticeChange}
      lens="open"
      onLensChange={onLensChange}
      {...over}
    />
  )
  return { onPracticeChange, onLensChange }
}

describe('FindingsBaseChips', () => {
  it('reads "Practice: Vulnerabilities" and "State: Open", never removable', () => {
    setup()
    expect(screen.getByRole('button', { name: 'Practice: Vulnerabilities' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'State: Open' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Clear/ })).toBeNull()
  })

  it('lists the practices that hold findings, without counts, and picks one', async () => {
    const { onPracticeChange } = setup()
    await userEvent.click(screen.getByRole('button', { name: 'Practice: Vulnerabilities' }))
    const items = await screen.findAllByRole('menuitemradio')
    expect(items.map((i) => i.textContent)).toEqual([
      'Vulnerabilities',
      'Compliance',
      'Application security',
      'External exposure',
      'All',
    ])
    await userEvent.click(screen.getByRole('menuitemradio', { name: 'Compliance' }))
    expect(onPracticeChange).toHaveBeenCalledWith('compliance')
  })

  it('changes the state lens', async () => {
    const { onLensChange } = setup()
    await userEvent.click(screen.getByRole('button', { name: 'State: Open' }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: 'Closed' }))
    expect(onLensChange).toHaveBeenCalledWith('closed')
  })

  it('says a saved view sets a scope until one is picked', () => {
    setup({ practiceFromView: true, lensFromView: true })
    expect(screen.getByRole('button', { name: 'Practice: Set by the view' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'State: Set by the view' })).toBeInTheDocument()
  })

  it('hides on a phone toolbar and shows in the phone filter sheet', () => {
    const { unmount } = render(
      <FindingsBaseChips
        practice="all"
        onPracticeChange={() => {}}
        lens="all"
        onLensChange={() => {}}
      />
    )
    expect(document.querySelector('[data-slot="filter-select"]')).toHaveClass('max-md:hidden')
    unmount()
    setup({ inSheet: true })
    expect(screen.getByTestId('findings-base-chips-sheet')).toHaveClass('md:hidden')
    expect(document.querySelector('[data-slot="filter-select"]')).not.toHaveClass('max-md:hidden')
  })
})
