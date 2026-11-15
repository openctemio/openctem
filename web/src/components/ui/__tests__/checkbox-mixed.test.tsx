/**
 * A mixed checkbox (some rows of a page checked) shows a dash and is filled
 * like a checked one, so it never reads as checked or as empty.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Checkbox } from '../checkbox'

describe('Checkbox', () => {
  it('draws a dash, filled, when mixed', () => {
    render(<Checkbox checked="indeterminate" aria-label="All rows" />)
    const box = screen.getByRole('checkbox', { name: 'All rows' })
    expect(box).toHaveAttribute('aria-checked', 'mixed')
    expect(box.className).toContain('data-[state=indeterminate]:bg-primary')
    expect(box.querySelector('.lucide-minus')).not.toBeNull()
    expect(box.querySelector('.lucide-check')).toBeNull()
  })

  it('draws a check when checked', () => {
    render(<Checkbox checked aria-label="Row" />)
    const box = screen.getByRole('checkbox', { name: 'Row' })
    expect(box.querySelector('.lucide-check')).not.toBeNull()
  })
})
