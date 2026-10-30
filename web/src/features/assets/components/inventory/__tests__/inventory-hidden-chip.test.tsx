import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TooltipProvider } from '@/components/ui/tooltip'
import { InventoryHiddenChip } from '../inventory-hidden-chip'

const renderChip = (count: number | undefined, onShowAll = () => {}) =>
  render(
    <TooltipProvider>
      <InventoryHiddenChip count={count} onShowAll={onShowAll} />
    </TooltipProvider>
  )

describe('InventoryHiddenChip', () => {
  it('renders nothing when nothing is hidden', () => {
    renderChip(0)
    expect(screen.queryByTestId('inventory-hidden-chip')).toBeNull()
  })

  it('renders nothing, and no claim, when the count is unknown', () => {
    renderChip(undefined)
    expect(screen.queryByTestId('inventory-hidden-chip')).toBeNull()
    expect(screen.queryByText(/hiding/i)).toBeNull()
  })

  it('names the count and offers Show and a Review link', async () => {
    const onShowAll = vi.fn()
    renderChip(80, onShowAll)
    expect(screen.getByTestId('inventory-hidden-chip')).toHaveTextContent(
      'Hiding 80 names awaiting review or not ours'
    )
    // Not dismissible: the only button shows everything.
    expect(screen.getAllByRole('button')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Show' }))
    expect(onShowAll).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('link', { name: 'Review' })).toHaveAttribute(
      'href',
      '/attack-surface/review'
    )
  })

  it('uses the singular for one name', () => {
    renderChip(1)
    expect(screen.getByTestId('inventory-hidden-chip')).toHaveTextContent(
      'Hiding 1 name awaiting review or not ours'
    )
  })
})
