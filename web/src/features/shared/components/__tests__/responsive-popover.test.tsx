import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
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

/** A phone: a coarse pointer that cannot hover. */
function emulateTouch() {
  vi.stubGlobal(
    'matchMedia',
    (query: string) =>
      ({
        matches: query.includes('pointer: coarse'),
        media: query,
        addEventListener() {},
        removeEventListener() {},
      }) as unknown as MediaQueryList
  )
}

function AddFilter({ onPick }: { onPick?: (field: string) => void }) {
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
            <CommandItem onSelect={() => onPick?.('kev')}>Known exploited (KEV)</CommandItem>
            <CommandItem onSelect={() => onPick?.('epss')}>EPSS score</CommandItem>
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
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('is the anchored popover from md up', async () => {
    const user = userEvent.setup()
    render(<AddFilter />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    const pop = await screen.findByRole('dialog', { name: 'Add filter' })
    expect(pop.closest('[data-slot="responsive-popover-sheet"]')).toBeNull()
    expect(pop).toHaveClass('w-80', 'p-0')
  })

  it('opens as a bottom sheet below md: title, search field pinned on top, the list uncapped; with a mouse the field has focus', async () => {
    mobile.value = true
    const user = userEvent.setup()
    render(<AddFilter />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    const sheet = await screen.findByRole('dialog', { name: 'Add filter' })
    expect(sheet).toHaveAttribute('data-slot', 'responsive-popover-sheet')
    // Sized by the dynamic viewport minus the keyboard inset, and never
    // taller than the visible part while the keyboard is up.
    expect(sheet.className).toContain('h-[min(calc(100dvh_-_var(--modal-kb,0px)')
    expect(sheet.className).toContain('calc(var(--modal-vvh,100dvh)_-_0.5rem)')
    const field = screen.getByPlaceholderText('Search fields…')
    await waitFor(() => expect(field).toHaveFocus())
    // A search keyboard, and 16px text so iOS does not zoom.
    expect(field).toHaveAttribute('inputmode', 'search')
    expect(field).toHaveAttribute('enterkeyhint', 'search')
    expect(field).toHaveClass('text-base', 'md:text-sm')
    const body = screen.getByTestId('responsive-popover-body')
    expect(body.className).toContain('[&_[data-slot=command-input-wrapper]]:sticky')
    expect(body.className).toContain('[&_[data-slot=command-list]]:max-h-none')
    // Section headers stay, and stick under the field.
    expect(screen.getByText('Exposure')).toBeInTheDocument()
    expect(screen.getByText('Finding')).toBeInTheDocument()
    expect(body.className).toContain('[&_[cmdk-group-heading]]:sticky')
    expect(body.className).toContain('[&_[data-slot=command-item]]:min-h-11')
  })

  it('on a touch screen opens without the keyboard: the list has focus, the first option active', async () => {
    mobile.value = true
    emulateTouch()
    const onPick = vi.fn()
    const user = userEvent.setup()
    render(<AddFilter onPick={onPick} />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    await screen.findByRole('dialog', { name: 'Add filter' })
    const field = screen.getByPlaceholderText('Search fields…')
    const list = screen.getByRole('listbox')
    await waitFor(() => expect(list).toHaveFocus())
    expect(field).not.toHaveFocus()
    const first = screen.getByRole('option', { name: 'Known exploited (KEV)' })
    expect(list).toHaveAttribute('aria-activedescendant', first.id)
    // An attached keyboard still works: down, then Enter picks.
    await user.keyboard('{ArrowDown}{Enter}')
    expect(onPick).toHaveBeenCalledWith('epss')
  })

  it('on a touch screen: Enter in the field picks the highlighted option, clearing keeps the field focused', async () => {
    mobile.value = true
    emulateTouch()
    const onPick = vi.fn()
    const user = userEvent.setup()
    render(<AddFilter onPick={onPick} />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    const field = await screen.findByPlaceholderText('Search fields…')
    await user.click(field)
    await user.keyboard('sev')
    await user.click(screen.getByRole('button', { name: 'Clear search' }))
    expect(field).toHaveValue('')
    expect(field).toHaveFocus()
    await user.keyboard('epss{Enter}')
    expect(onPick).toHaveBeenCalledWith('epss')
  })

  it('blurs the field when the sheet closes, so the keyboard goes with it', async () => {
    mobile.value = true
    emulateTouch()
    const user = userEvent.setup()
    render(<AddFilter />)
    await user.click(screen.getByRole('button', { name: 'Add filter' }))
    const field = await screen.findByPlaceholderText('Search fields…')
    await user.click(field)
    const blur = vi.fn()
    field.addEventListener('blur', blur)
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(blur).toHaveBeenCalled()
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
