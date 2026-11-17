import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TooltipProvider } from '@/components/ui/tooltip'
import { AddFilterPanel } from '../add-filter-panel'

function renderPanel() {
  return render(
    <TooltipProvider>
      <input aria-label="Search" />
      <AddFilterPanel>
        <p>Status facet</p>
      </AddFilterPanel>
    </TooltipProvider>
  )
}

describe('AddFilterPanel', () => {
  it('opens the facets from the shared Add filter button', async () => {
    renderPanel()
    expect(screen.queryByText('Status facet')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /add filter/i }))
    expect(await screen.findByText('Status facet')).toBeInTheDocument()
    expect(document.querySelector('[data-slot="add-filter-panel"]')).not.toBeNull()
  })

  it('opens on f outside a text field, not while typing', async () => {
    renderPanel()
    await userEvent.click(screen.getByLabelText('Search'))
    await userEvent.keyboard('f')
    expect(screen.queryByText('Status facet')).toBeNull()
    ;(document.activeElement as HTMLElement).blur()
    await userEvent.keyboard('f')
    expect(await screen.findByText('Status facet')).toBeInTheDocument()
  })
})
