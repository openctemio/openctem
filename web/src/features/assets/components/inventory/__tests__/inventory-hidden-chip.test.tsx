import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TooltipProvider } from '@/components/ui/tooltip'
import { InventoryHiddenChip } from '../inventory-hidden-chip'

describe('InventoryHiddenChip', () => {
  it('says what the default list hides and offers one action, Show', async () => {
    const onShowAll = vi.fn()
    render(
      <TooltipProvider>
        <InventoryHiddenChip onShowAll={onShowAll} />
      </TooltipProvider>
    )
    expect(screen.getByTestId('inventory-hidden-chip')).toHaveTextContent(
      'Hiding names awaiting review and not ours'
    )
    // Not dismissible: the only button shows everything.
    const buttons = screen.getAllByRole('button')
    expect(buttons).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Show' }))
    expect(onShowAll).toHaveBeenCalledTimes(1)
  })

  it('names how many it hides when the view has no other filter', () => {
    const { rerender } = render(
      <TooltipProvider>
        <InventoryHiddenChip count={80} onShowAll={() => {}} />
      </TooltipProvider>
    )
    expect(screen.getByTestId('inventory-hidden-chip')).toHaveTextContent(
      'Hiding 80 names awaiting review or not ours'
    )
    rerender(
      <TooltipProvider>
        <InventoryHiddenChip count={1} onShowAll={() => {}} />
      </TooltipProvider>
    )
    expect(screen.getByTestId('inventory-hidden-chip')).toHaveTextContent(
      'Hiding 1 name awaiting review or not ours'
    )
  })
})
