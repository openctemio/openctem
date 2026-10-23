import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { SidebarInset } from '../sidebar'

describe('SidebarInset', () => {
  it('is a flat content area: no outer margin, radius or shadow classes', () => {
    const { container } = render(<SidebarInset />)
    const cls = container.querySelector('[data-slot="sidebar-inset"]')?.className ?? ''
    expect(cls).not.toMatch(/rounded|shadow|(^|\s|:)m[se]?-\d|variant=inset/)
    expect(cls).toContain('bg-background')
  })
})
