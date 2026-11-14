import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Button } from '../button'

describe('Button transitions', () => {
  it('changes colour without animation unless hovered or focused (no flash on load)', () => {
    render(<Button>Go</Button>)
    const cls = screen.getByRole('button', { name: 'Go' }).className
    expect(cls).not.toMatch(/(^|\s)transition-all(\s|$)/)
    expect(cls).toMatch(/(^|\s)transition-none(\s|$)/)
    expect(cls).toMatch(/\bhover:transition-\[/)
    expect(cls).toMatch(/\bfocus-visible:transition-\[/)
  })
})
