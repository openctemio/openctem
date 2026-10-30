import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useState } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { ResponsivePopover } from '../responsive-popover'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.scrollIntoView ??= function () {}

const mobile = vi.hoisted(() => ({ value: false }))
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => mobile.value }))

function AddFilter() {
  const [open, setOpen] = useState(false)
  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title="Add filter"
      className="w-80"
      trigger={<button type="button">Add filter</button>}
    >
      <Command>
        <CommandInput placeholder="Search fields…" />
        <CommandList>
          <CommandGroup heading="Exposure">
            <CommandItem>Known exploited (KEV)</CommandItem>
            <CommandItem>EPSS score</CommandItem>
          </CommandGroup>
          <CommandGroup heading="Finding">
            <CommandItem>Severity</CommandItem>
          </CommandGroup>
        </CommandList>
      </Command>
    </ResponsivePopover>
  )
}

describe('ResponsivePopover', () => {
  beforeEach(() => {
    mobile.value = false
  })

  it('is the anchored popover from md up', async () => {
    const user = userEvent.setup()
    render(<AddFilter />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    const pop = await screen.findByRole('dialog', { name: 'Add filter' })
    expect(pop.closest('[data-slot="responsive-popover-sheet"]')).toBeNull()
    expect(pop).toHaveClass('w-80', 'p-0')
  })

  it('opens as a bottom sheet on a phone: title, focused search field pinned on top, the list uncapped', async () => {
    mobile.value = true
    const user = userEvent.setup()
    render(<AddFilter />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    const sheet = await screen.findByRole('dialog', { name: 'Add filter' })
    expect(sheet).toHaveAttribute('data-slot', 'responsive-popover-sheet')
    // Sized by the dynamic viewport minus the keyboard inset.
    expect(sheet.className).toContain('h-[calc(100dvh-var(--modal-kb,0px)')
    const field = screen.getByPlaceholderText('Search fields…')
    await waitFor(() => expect(field).toHaveFocus())
    // A search keyboard, and 16px text so iOS does not zoom.
    expect(field).toHaveAttribute('inputmode', 'search')
    expect(field).toHaveAttribute('enterkeyhint', 'search')
    expect(field).toHaveClass('text-base', 'md:text-sm')
    const body = screen.getByTestId('responsive-popover-body')
    expect(body.className).toContain('[&_[data-slot=command-input-wrapper]]:sticky')
    expect(body.className).toContain('[&_[data-slot=command-list]]:max-h-none')
    // Section headers stay.
    expect(screen.getByText('Exposure')).toBeInTheDocument()
    expect(screen.getByText('Finding')).toBeInTheDocument()
  })

  it('returns focus to the trigger when the sheet closes', async () => {
    mobile.value = true
    const user = userEvent.setup()
    render(<AddFilter />)
    const trigger = screen.getByRole('button', { name: 'Add filter' })
    await user.click(trigger)
    await screen.findByRole('dialog', { name: 'Add filter' })
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(trigger).toHaveFocus()
  })
})
