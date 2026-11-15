import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  TOUCH_TYPING_SURFACES,
  isTouchPrimary,
  opensWithTextFocus,
} from '@/components/ui/touch-focus'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Dialog, DialogBody, DialogContent, DialogTitle } from '@/components/ui/dialog'
import {
  Command,
  CommandDialog,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.scrollIntoView ??= function () {}

/** A phone (coarse, no hover) or a desktop (fine pointer, hover). */
function emulate(kind: 'touch' | 'pointer') {
  const queries: string[] = []
  vi.stubGlobal('matchMedia', (query: string) => {
    queries.push(query)
    return {
      matches:
        kind === 'touch' && query.includes('pointer: coarse') && query.includes('hover: none'),
      media: query,
      addEventListener() {},
      removeEventListener() {},
    } as unknown as MediaQueryList
  })
  return queries
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('isTouchPrimary', () => {
  it('is false without matchMedia (server, old browsers)', () => {
    vi.stubGlobal('matchMedia', undefined)
    expect(isTouchPrimary()).toBe(false)
  })

  it('asks for a coarse pointer that cannot hover', () => {
    const queries = emulate('touch')
    expect(isTouchPrimary()).toBe(true)
    expect(queries).toContain('(pointer: coarse) and (hover: none)')
  })

  it('is false with a mouse or trackpad', () => {
    emulate('pointer')
    expect(isTouchPrimary()).toBe(false)
  })
})

describe('opensWithTextFocus', () => {
  it('pointer: always', () => {
    emulate('pointer')
    expect(opensWithTextFocus()).toBe(true)
  })

  it('touch: only for a listed typing surface', () => {
    emulate('touch')
    expect(opensWithTextFocus()).toBe(false)
    for (const id of Object.keys(TOUCH_TYPING_SURFACES) as (keyof typeof TOUCH_TYPING_SURFACES)[])
      expect(opensWithTextFocus(id)).toBe(true)
  })

  it('lists the exceptions in one place', () => {
    expect(Object.keys(TOUCH_TYPING_SURFACES).sort()).toEqual([
      'command-menu',
      'single-field',
      'step-up',
      'type-to-confirm',
    ])
  })
})

function Picker() {
  return (
    <Popover>
      <PopoverTrigger>Owner</PopoverTrigger>
      <PopoverContent aria-label="Owner">
        <Command>
          <CommandInput placeholder="Search people" />
          <CommandList>
            <CommandItem>Ann</CommandItem>
            <CommandItem>Bao</CommandItem>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

describe('picker popover (Command inside PopoverContent)', () => {
  it('touch: the search field is not focused on open; the list is, with the first option active', async () => {
    emulate('touch')
    const user = userEvent.setup()
    render(<Picker />)
    await user.click(screen.getByRole('button', { name: 'Owner' }))
    const list = await screen.findByRole('listbox')
    await waitFor(() => expect(list).toHaveFocus())
    expect(screen.getByPlaceholderText('Search people')).not.toHaveFocus()
    expect(list).toHaveAttribute(
      'aria-activedescendant',
      screen.getByRole('option', { name: 'Ann' }).id
    )
  })

  it('pointer: the search field has focus on open, as before', async () => {
    emulate('pointer')
    const user = userEvent.setup()
    render(<Picker />)
    await user.click(screen.getByRole('button', { name: 'Owner' }))
    await waitFor(() => expect(screen.getByPlaceholderText('Search people')).toHaveFocus())
  })
})

function FieldPopover({ typing }: { typing?: boolean }) {
  return (
    <Popover>
      <PopoverTrigger>Add label</PopoverTrigger>
      <PopoverContent aria-label="Add label" typingSurface={typing ? 'single-field' : undefined}>
        <button type="button">Help</button>
        <Input aria-label="Label" autoFocus />
      </PopoverContent>
    </Popover>
  )
}

describe('autoFocus of a kit field inside a surface', () => {
  it('touch: dropped inside a popover', async () => {
    emulate('touch')
    const user = userEvent.setup()
    render(<FieldPopover />)
    await user.click(screen.getByRole('button', { name: 'Add label' }))
    await screen.findByRole('dialog', { name: 'Add label' })
    expect(screen.getByRole('textbox', { name: 'Label' })).not.toHaveFocus()
  })

  it('touch: kept on a listed typing surface', async () => {
    emulate('touch')
    const user = userEvent.setup()
    render(<FieldPopover typing />)
    await user.click(screen.getByRole('button', { name: 'Add label' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Label' })).toHaveFocus())
  })

  it('pointer: kept', async () => {
    emulate('pointer')
    const user = userEvent.setup()
    render(<FieldPopover />)
    await user.click(screen.getByRole('button', { name: 'Add label' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Label' })).toHaveFocus())
  })

  it('touch: kept for a field revealed by a tap inside the open surface (Edit name)', async () => {
    emulate('touch')
    function Rename() {
      const [editing, setEditing] = useState(false)
      return (
        <Popover>
          <PopoverTrigger>Group</PopoverTrigger>
          <PopoverContent aria-label="Group">
            {editing ? (
              <Input aria-label="Name" autoFocus />
            ) : (
              <button type="button" onClick={() => setEditing(true)}>
                Edit name
              </button>
            )}
          </PopoverContent>
        </Popover>
      )
    }
    const user = userEvent.setup()
    render(<Rename />)
    await user.click(screen.getByRole('button', { name: 'Group' }))
    await user.click(await screen.findByRole('button', { name: 'Edit name' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Name' })).toHaveFocus())
  })

  it('touch: kept outside any surface (an inline form is not a popup)', () => {
    emulate('touch')
    render(<Textarea aria-label="Note" autoFocus />)
    expect(screen.getByRole('textbox', { name: 'Note' })).toHaveFocus()
  })

  it('touch: a dialog focuses its body, unless it is a typing surface', async () => {
    emulate('touch')
    const { rerender } = render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Confirm</DialogTitle>
          <DialogBody>
            <Input aria-label="Reason" autoFocus />
          </DialogBody>
        </DialogContent>
      </Dialog>
    )
    const field = screen.getByRole('textbox', { name: 'Reason' })
    await waitFor(() => expect(field.closest('[data-slot="dialog-body"]')).toHaveFocus())
    expect(field).not.toHaveFocus()
    rerender(
      <Dialog open={false}>
        <DialogContent>
          <DialogTitle>Confirm</DialogTitle>
        </DialogContent>
      </Dialog>
    )
    rerender(
      <Dialog open>
        <DialogContent typingSurface="step-up">
          <DialogTitle>Confirm</DialogTitle>
          <DialogBody>
            <Input aria-label="Code" autoFocus />
          </DialogBody>
        </DialogContent>
      </Dialog>
    )
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Code' })).toHaveFocus())
  })

  it('touch: a command palette focuses its search (listed exception)', async () => {
    emulate('touch')
    render(
      <CommandDialog open title="Search">
        <CommandInput placeholder="Type a command" />
        <CommandList>
          <CommandItem>Findings</CommandItem>
        </CommandList>
      </CommandDialog>
    )
    await waitFor(() => expect(screen.getByPlaceholderText('Type a command')).toHaveFocus())
  })
})
