import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Button } from '../button'
import { DensityScope, EntryScope } from '../density'
import { Input } from '../input'

/**
 * The control scale lives in the kit (web/docs/ui-style-contract.md): 32 by
 * default, the small sizes 28 only in a dense place (CSS reads
 * data-control-density), 36 on entry pages. Below 768px the live UI's
 * heights (36, sm 32, lg 40; fields 36 with 16px text), compact button
 * content and a 44px-tall invisible touch target.
 */
describe('control scale', () => {
  it('sizes buttons from the scale tokens; the live heights below 768px', () => {
    render(
      <>
        <Button>Default</Button>
        <Button size="sm">Small</Button>
        <Button size="lg">Entry</Button>
        <Button size="icon" aria-label="Icon" />
        <Button size="icon-sm" aria-label="Small icon" />
        <Button size="xs" aria-label="Info" />
      </>
    )
    const cls = (name: string) => screen.getByRole('button', { name }).className
    expect(cls('Default')).toMatch(/\bh-control\b/)
    expect(cls('Default')).toMatch(/\bmax-md:text-dense\b/)
    expect(cls('Default')).toMatch(/\bmax-md:before:h-touch-target\b/)
    expect(cls('Default')).toMatch(/\bmax-md:h-control-touch\b/)
    expect(cls('Small')).toMatch(/\bmax-md:h-control-touch-dense\b/)
    expect(cls('Entry')).toMatch(/\bmax-md:h-control-touch-lg\b/)
    expect(cls('Icon')).toMatch(/\bmax-md:size-control-touch\b/)
    expect(cls('Small icon')).toMatch(/\bmax-md:size-control-touch-dense\b/)
    expect(cls('Small')).toMatch(/\bh-control-dense\b/)
    expect(cls('Entry')).toMatch(/\bh-control-entry\b/)
    expect(cls('Icon')).toMatch(/\bsize-control\b/)
    expect(cls('Small icon')).toMatch(/\bsize-control-dense\b/)
    expect(cls('Info')).toMatch(/\bsize-control-xs\b/)
    for (const name of ['Default', 'Small', 'Entry'])
      expect(cls(name)).not.toMatch(/\bh-(8|9|10)\b/)
  })

  it('a button that is icon-only below a width is a square there', () => {
    render(
      <Button iconOnlyBelow="sm" size="sm">
        <svg aria-hidden />
        <span className="sr-only sm:not-sr-only">Approvals</span>
      </Button>
    )
    const cls = screen.getByRole('button', { name: 'Approvals' }).className
    expect(cls).toMatch(/\bmax-sm:aspect-square\b/)
    expect(cls).toMatch(/\bmax-sm:px-0\b/)
  })

  it('changes colour without animation unless hovered or focused (no flash on load)', () => {
    render(<Button>Go</Button>)
    const cls = screen.getByRole('button', { name: 'Go' }).className
    expect(cls).not.toMatch(/(^|\s)transition-all(\s|$)/)
    expect(cls).toMatch(/(^|\s)transition-none(\s|$)/)
    expect(cls).toMatch(/\bhover:transition-\[/)
    expect(cls).toMatch(/\bfocus-visible:transition-\[/)
  })

  it('has no signal variant: the main action is ink', () => {
    render(<Button>Go</Button>)
    expect(screen.getByRole('button', { name: 'Go' }).className).toContain('bg-primary')
  })

  it('a text field shares the row height', () => {
    render(<Input aria-label="Name" />)
    expect(screen.getByRole('textbox', { name: 'Name' }).className).toMatch(
      /\bh-control-field\b.*\bmax-md:h-control-touch\b/
    )
  })

  it('marks dense and entry places for CSS without a layout box', () => {
    const { container } = render(
      <>
        <DensityScope>
          <Button size="sm">Row action</Button>
        </DensityScope>
        <EntryScope>
          <Button>Sign in</Button>
        </EntryScope>
      </>
    )
    const dense = container.querySelector('[data-control-density="dense"]')
    const entry = container.querySelector('[data-control-scale="entry"]')
    expect(dense).toHaveClass('contents')
    expect(entry).toHaveClass('contents')
    expect(dense).toContainElement(screen.getByRole('button', { name: 'Row action' }))
  })
})
