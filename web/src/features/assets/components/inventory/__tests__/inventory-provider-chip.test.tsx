import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TooltipProvider } from '@/components/ui/tooltip'
import { InventoryProviderChip } from '../inventory-provider-chip'

const renderChip = (count: number | undefined, onShow = () => {}) =>
  render(
    <TooltipProvider>
      <InventoryProviderChip count={count} onShow={onShow} />
    </TooltipProvider>
  )

// research/531: provider addresses leave the default list behind one chip.
describe('InventoryProviderChip', () => {
  it('renders nothing when there are none or the count is unknown', () => {
    renderChip(0)
    renderChip(undefined)
    expect(screen.queryByTestId('inventory-provider-chip')).toBeNull()
  })

  it('names the count and Show lists them', async () => {
    const onShow = vi.fn()
    renderChip(565, onShow)
    expect(screen.getByTestId('inventory-provider-chip')).toHaveTextContent(
      'Provider addresses (565)'
    )
    await userEvent.click(screen.getByRole('button', { name: /show/i }))
    expect(onShow).toHaveBeenCalledTimes(1)
  })
})
