/**
 * The shared modal frame (components/ui/modal-layout.tsx): a fixed header,
 * a body that is the only scroll container, a fixed footer, for Dialog,
 * AlertDialog and Sheet.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'

import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '../dialog'
import {
  AlertDialog,
  AlertDialogBody,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../alert-dialog'
import { Sheet, SheetBody, SheetContent, SheetHeader, SheetTitle } from '../sheet'

const realMatchMedia = window.matchMedia
const realVisualViewport = Object.getOwnPropertyDescriptor(window, 'visualViewport')
const realScrollIntoView = Element.prototype.scrollIntoView

afterEach(() => {
  window.matchMedia = realMatchMedia
  if (realVisualViewport) Object.defineProperty(window, 'visualViewport', realVisualViewport)
  else delete (window as { visualViewport?: unknown }).visualViewport
  Element.prototype.scrollIntoView = realScrollIntoView
  vi.restoreAllMocks()
})

function pointer(coarse: boolean) {
  window.matchMedia = ((q: string) => ({
    matches: coarse && q.includes('coarse'),
    media: q,
    addEventListener() {},
    removeEventListener() {},
  })) as unknown as typeof window.matchMedia
}

function FormDialog({
  onSubmit = () => {},
  withBody = true,
}: {
  onSubmit?: () => void
  withBody?: boolean
}) {
  const [open, setOpen] = useState(false)
  const fields = (
    <>
      <p>Intro</p>
      <input aria-label="Title" />
    </>
  )
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger>Open</DialogTrigger>
      <DialogContent size="lg">
        <DialogHeader actions={<span>Draft</span>}>
          <DialogTitle>Add finding</DialogTitle>
          <DialogDescription>Required fields are marked.</DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            onSubmit()
          }}
        >
          {withBody ? <DialogBody>{fields}</DialogBody> : fields}
          <DialogFooter>
            <button type="button">Cancel</button>
            <button type="submit">Create</button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

describe('Dialog with a DialogBody', () => {
  it('lays out header, body and footer as sections, the close button in the header', async () => {
    pointer(false)
    const user = userEvent.setup()
    render(<FormDialog />)
    await user.click(screen.getByRole('button', { name: 'Open' }))

    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveAttribute('data-layout', 'sections')
    expect(dialog.className).toContain('overflow-hidden')
    expect(dialog.className).not.toContain('overflow-y-auto')
    expect(dialog.className).toContain('sm:max-w-2xl')

    const header = dialog.querySelector('[data-slot="dialog-header"]')!
    const body = dialog.querySelector('[data-slot="dialog-body"]')!
    const footer = dialog.querySelector('[data-slot="dialog-footer"]')!
    expect(body.className).toContain('overflow-y-auto')
    expect(body.className).toContain('flex-1')
    expect(header.className).toContain('shrink-0')
    expect(footer.className).toContain('shrink-0')

    const closes = screen.getAllByRole('button', { name: 'Close' })
    expect(closes).toHaveLength(1)
    expect(header).toContainElement(closes[0])
    expect(closes[0].className).not.toContain('absolute')
    expect(header).toHaveTextContent('Draft')
    // Title and description still name the dialog.
    expect(dialog).toHaveAccessibleName('Add finding')
    expect(dialog).toHaveAccessibleDescription('Required fields are marked.')
  })

  it('opens on the first field, not the close button; Escape closes and returns focus', async () => {
    pointer(false)
    const user = userEvent.setup()
    render(<FormDialog />)
    const trigger = screen.getByRole('button', { name: 'Open' })
    await user.click(trigger)
    expect(screen.getByRole('textbox', { name: 'Title' })).toHaveFocus()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('on a touch screen opens on the body, so the keyboard does not pop up', async () => {
    pointer(true)
    const user = userEvent.setup()
    render(<FormDialog />)
    await user.click(screen.getByRole('button', { name: 'Open' }))
    expect(document.querySelector('[data-slot="dialog-body"]')).toHaveFocus()
  })

  it('submits from Enter in a field and from the footer button', async () => {
    pointer(false)
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<FormDialog onSubmit={onSubmit} />)
    await user.click(screen.getByRole('button', { name: 'Open' }))
    await user.type(screen.getByRole('textbox', { name: 'Title' }), 'SQLi{Enter}')
    expect(onSubmit).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(onSubmit).toHaveBeenCalledTimes(2)
  })

  it('shows a divider only on the side where content is hidden', async () => {
    pointer(false)
    const user = userEvent.setup()
    render(<FormDialog />)
    await user.click(screen.getByRole('button', { name: 'Open' }))
    const body = document.querySelector<HTMLElement>('[data-slot="dialog-body"]')!
    Object.defineProperty(body, 'scrollHeight', { configurable: true, value: 1000 })
    Object.defineProperty(body, 'clientHeight', { configurable: true, value: 400 })

    body.scrollTop = 0
    fireEvent.scroll(body)
    expect(body).not.toHaveAttribute('data-overflow-top')
    expect(body).toHaveAttribute('data-overflow-bottom')

    body.scrollTop = 300
    fireEvent.scroll(body)
    expect(body).toHaveAttribute('data-overflow-top')
    expect(body).toHaveAttribute('data-overflow-bottom')

    body.scrollTop = 600
    fireEvent.scroll(body)
    expect(body).toHaveAttribute('data-overflow-top')
    expect(body).not.toHaveAttribute('data-overflow-bottom')
  })

  it('stays above the on-screen keyboard and brings the focused field back into view', async () => {
    pointer(false)
    const vv = Object.assign(new EventTarget(), {
      height: window.innerHeight,
      width: window.innerWidth,
      offsetTop: 0,
      offsetLeft: 0,
      scale: 1,
    })
    Object.defineProperty(window, 'visualViewport', { configurable: true, get: () => vv })
    const scrolled = vi.fn()
    Element.prototype.scrollIntoView = scrolled

    const user = userEvent.setup()
    render(<FormDialog />)
    await user.click(screen.getByRole('button', { name: 'Open' }))
    const dialog = screen.getByRole('dialog')
    const field = screen.getByRole('textbox', { name: 'Title' })
    expect(field).toHaveFocus()

    act(() => {
      vv.height = window.innerHeight - 300
      vv.dispatchEvent(new Event('resize'))
    })
    expect(dialog.style.getPropertyValue('--modal-kb')).toBe('300px')
    // The phone surface is lifted by that height and loses it from its max height.
    expect(dialog.className).toContain('bottom-[var(--modal-kb,0px)]')
    expect(dialog.className).toContain('max-h-[calc(100dvh-var(--modal-kb,0px)')
    await waitFor(() => expect(scrolled).toHaveBeenCalled())
    expect(scrolled.mock.contexts[0]).toBe(field)

    act(() => {
      vv.height = window.innerHeight
      vv.dispatchEvent(new Event('resize'))
    })
    expect(dialog.style.getPropertyValue('--modal-kb')).toBe('0px')
  })
})

describe('Dialog without a DialogBody', () => {
  it('keeps the single padded block with the corner close button', async () => {
    pointer(false)
    const user = userEvent.setup()
    render(<FormDialog withBody={false} />)
    await user.click(screen.getByRole('button', { name: 'Open' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveAttribute('data-layout', 'block')
    expect(dialog.className).toContain('overflow-y-auto')
    const close = screen.getByRole('button', { name: 'Close' })
    expect(close.className).toContain('absolute')
    expect(dialog.querySelector('[data-slot="dialog-header"]')).not.toContainElement(close)
    // Radix default focus: the first focusable element, the field.
    expect(screen.getByRole('textbox', { name: 'Title' })).toHaveFocus()
  })
})

describe('AlertDialog with an AlertDialogBody', () => {
  it('uses the same sections, has no close button and opens on Cancel', async () => {
    render(
      <AlertDialog open>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete 3 assets?</AlertDialogTitle>
            <AlertDialogDescription>This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogBody>
            <ul>
              <li>a</li>
            </ul>
          </AlertDialogBody>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <button>Delete</button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )
    const dialog = screen.getByRole('alertdialog')
    expect(dialog).toHaveAttribute('data-layout', 'sections')
    expect(dialog.querySelector('[data-slot="alert-dialog-body"]')!.className).toContain(
      'overflow-y-auto'
    )
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus())
  })
})

describe('Sheet with a SheetBody', () => {
  it('pins the header with its actions and the close button; only the body scrolls', () => {
    render(
      <Sheet open>
        <SheetContent>
          <SheetHeader actions={<button>Edit</button>}>
            <SheetTitle>Run 42</SheetTitle>
          </SheetHeader>
          <SheetBody>
            <p>steps</p>
          </SheetBody>
        </SheetContent>
      </Sheet>
    )
    const sheet = screen.getByRole('dialog')
    expect(sheet).toHaveAttribute('data-layout', 'sections')
    expect(sheet.className).toContain('overflow-hidden')
    const header = sheet.querySelector('[data-slot="sheet-header"]')!
    expect(header).toContainElement(screen.getByRole('button', { name: 'Close' }))
    expect(header).toContainElement(screen.getByRole('button', { name: 'Edit' }))
    expect(sheet.querySelector('[data-slot="sheet-body"]')!.className).toContain('overflow-y-auto')
  })

  it('can drop the close button', () => {
    render(
      <Sheet open>
        <SheetContent showCloseButton={false}>
          <SheetHeader>
            <SheetTitle>Run 42</SheetTitle>
          </SheetHeader>
          <SheetBody />
        </SheetContent>
      </Sheet>
    )
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
  })
})
