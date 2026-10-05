import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Box } from 'lucide-react'
import { ContextFilterChips, type ContextFilterChip } from '../context-filter-chips'

// Focusing a chip opens its tooltip; Radix's popper measures with ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const asset = (over: Partial<ContextFilterChip> = {}): ContextFilterChip => ({
  param: 'asset_id',
  kind: 'Asset',
  icon: Box,
  fixedWidth: true,
  label: 'web-01.example.com',
  ...over,
})

describe('ContextFilterChips', () => {
  it('renders nothing without chips (no empty slot that could change height)', () => {
    const { container } = render(<ContextFilterChips chips={[]} onRemove={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the kind and the label as plain text in a labelled list', () => {
    render(<ContextFilterChips chips={[asset()]} onRemove={() => {}} />)
    const list = screen.getByRole('list', { name: 'Context filters' })
    expect(list).toHaveTextContent('Asset')
    expect(list).toHaveTextContent('web-01.example.com')
  })

  it('renders an attacker-influenced label as text, never as markup', () => {
    render(
      <ContextFilterChips
        chips={[asset({ label: '<img src=x onerror=alert(1)>' })]}
        onRemove={() => {}}
      />
    )
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent(
      '<img src=x onerror=alert(1)>'
    )
  })

  it('shows bidi overrides and line breaks as visible escapes, isolated', () => {
    render(
      <ContextFilterChips
        chips={[asset({ label: 'evil‮moc.elgoog\nsecond row' })]}
        onRemove={() => {}}
      />
    )
    const slot = screen.getByTestId('context-chip-asset_id-label')
    expect(slot.textContent).not.toContain('‮')
    expect(slot.textContent).not.toContain('\n')
    expect(slot.textContent).toContain('\\u{202E}')
    expect(slot).toHaveAttribute('dir', 'auto')
  })

  it('caps a very long label', () => {
    render(<ContextFilterChips chips={[asset({ label: 'a'.repeat(5000) })]} onRemove={() => {}} />)
    const text = screen.getByTestId('context-chip-asset_id-label').textContent ?? ''
    expect(text.length).toBeLessThanOrEqual(201)
  })

  it('keeps the label slot the same fixed width while loading and once loaded', () => {
    const { rerender } = render(
      <ContextFilterChips chips={[asset({ loading: true })]} onRemove={() => {}} />
    )
    const loadingSlot = screen.getByTestId('context-chip-asset_id-label')
    expect(screen.getByTestId('context-chip-asset_id-placeholder')).toBeInTheDocument()
    expect(loadingSlot).toHaveClass('w-32')
    expect(screen.getByTestId('context-chip-asset_id')).toHaveAttribute('aria-busy', 'true')

    rerender(<ContextFilterChips chips={[asset()]} onRemove={() => {}} />)
    const loadedSlot = screen.getByTestId('context-chip-asset_id-label')
    // Same element (not remounted) with the same width class: no resize, no flash.
    expect(loadedSlot).toBe(loadingSlot)
    expect(loadedSlot).toHaveClass('w-32')
    expect(loadedSlot).toHaveClass('truncate')
    expect(screen.queryByTestId('context-chip-asset_id-placeholder')).toBeNull()
    expect(loadedSlot).toHaveTextContent('web-01.example.com')
  })

  it('keeps focus on the remove button when the label resolves', () => {
    const { rerender } = render(
      <ContextFilterChips chips={[asset({ loading: true })]} onRemove={() => {}} />
    )
    const button = screen.getByRole('button', { name: 'Remove asset filter' })
    button.focus()
    rerender(<ContextFilterChips chips={[asset()]} onRemove={() => {}} />)
    const after = screen.getByRole('button', { name: 'Remove asset filter: web-01.example.com' })
    expect(after).toBe(button)
    expect(after).toHaveFocus()
  })

  it('removes only the chip that was clicked, by its URL parameter', () => {
    const onRemove = vi.fn()
    render(
      <ContextFilterChips
        chips={[asset(), { param: 'cve_id', kind: 'CVE', label: 'CVE-2024-1234', mono: true }]}
        onRemove={onRemove}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Remove CVE filter: CVE-2024-1234' }))
    expect(onRemove).toHaveBeenCalledTimes(1)
    expect(onRemove).toHaveBeenCalledWith('cve_id')
  })

  it('remove buttons are real buttons with a visible focus ring', () => {
    render(<ContextFilterChips chips={[asset()]} onRemove={() => {}} />)
    const button = screen.getByRole('button', { name: /Remove asset filter/ })
    expect(button.tagName).toBe('BUTTON')
    expect(button).toHaveAttribute('type', 'button')
    expect(button.className).toContain('focus-visible:ring-2')
  })

  it('never grows wider than the toolbar (no sideways scroll on a phone)', () => {
    render(<ContextFilterChips chips={[asset()]} onRemove={() => {}} />)
    const list = screen.getByTestId('context-filter-chips')
    expect(list).toHaveClass('min-w-0', 'max-w-full', 'flex-wrap')
    expect(screen.getByTestId('context-chip-asset_id')).toHaveClass('max-w-full', 'h-7')
  })
})
