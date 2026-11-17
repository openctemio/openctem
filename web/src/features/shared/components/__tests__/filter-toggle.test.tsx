import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { Star } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { FilterToggle } from '../filter-toggle'

describe('FilterToggle', () => {
  it('is a pressed/unpressed token of the toolbar height that flips on click', () => {
    const onPressedChange = vi.fn()
    const { rerender } = render(
      <FilterToggle
        label="Primary assets"
        icon={Star}
        pressed={false}
        onPressedChange={onPressedChange}
      />
    )
    const token = screen.getByRole('button', { name: 'Primary assets' })
    expect(token).toHaveAttribute('aria-pressed', 'false')
    expect(token).toHaveAttribute('data-slot', 'filter-toggle')
    // The toolbar's control size (32, 36 on a phone).
    expect(token).toHaveAttribute('data-size', 'sm')
    fireEvent.click(token)
    expect(onPressedChange).toHaveBeenCalledWith(true)

    const off = token.className
    rerender(
      <FilterToggle label="Primary assets" icon={Star} pressed onPressedChange={onPressedChange} />
    )
    expect(token).toHaveAttribute('aria-pressed', 'true')
    // One box in both states: the same classes (the border stays), the fill by aria-pressed.
    expect(token.className).toBe(off)
    expect(token.className).toMatch(/(^|\s)border(\s|$)/)
    expect(token.className).toContain('aria-pressed:bg-secondary')
    fireEvent.click(token)
    expect(onPressedChange).toHaveBeenLastCalledWith(false)
  })

  it('shows the short label on a phone and keeps the full one as its tooltip', () => {
    render(
      <FilterToggle
        label="Internet-facing only"
        shortLabel="Internet-facing"
        pressed={false}
        onPressedChange={() => {}}
      />
    )
    const token = screen.getByRole('button')
    expect(token).toHaveAttribute('title', 'Internet-facing only')
    expect(screen.getByText('Internet-facing only')).toHaveClass('max-md:hidden')
    expect(screen.getByText('Internet-facing')).toHaveClass('md:hidden')
  })

  it('stays visible and disabled with its reason when it cannot be changed', () => {
    const onPressedChange = vi.fn()
    render(
      <TooltipProvider>
        <FilterToggle
          label="Primary assets"
          pressed={false}
          onPressedChange={onPressedChange}
          disabledReason="Turned on by the saved view"
        />
      </TooltipProvider>
    )
    const token = screen.getByRole('button', { name: 'Primary assets' })
    expect(token).toBeDisabled()
    expect(screen.getByLabelText('Turned on by the saved view')).toBeInTheDocument()
    fireEvent.click(token)
    expect(onPressedChange).not.toHaveBeenCalled()
  })
})
