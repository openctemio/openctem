/**
 * Every floating surface of the kit keeps the page gutter from the screen
 * edges. Radix defaults collisionPadding to 0, so a right-aligned menu whose
 * trigger sat at the left of a phone row (the page-header More once the
 * actions wrapped) opened flush against the left edge.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import * as React from 'react'

const seen: Record<string, unknown> = {}

function capture(name: string) {
  return function Captured({ collisionPadding }: { collisionPadding?: unknown }) {
    seen[name] = collisionPadding
    return null
  }
}

function Passthrough({ children }: { children?: React.ReactNode }) {
  return <>{children}</>
}

vi.mock('@radix-ui/react-dropdown-menu', () => ({
  Portal: Passthrough,
  Content: capture('dropdown'),
  SubContent: capture('dropdownSub'),
}))
vi.mock('@radix-ui/react-popover', () => ({
  Portal: Passthrough,
  Content: capture('popover'),
}))
vi.mock('@radix-ui/react-tooltip', () => ({
  Portal: Passthrough,
  Content: capture('tooltip'),
  Arrow: () => null,
}))
vi.mock('@radix-ui/react-select', () => ({
  Portal: Passthrough,
  Content: capture('select'),
  Viewport: Passthrough,
  ScrollUpButton: Passthrough,
  ScrollDownButton: Passthrough,
}))

import { FLOATING_COLLISION_PADDING } from '../floating'
import { DropdownMenuContent, DropdownMenuSubContent } from '../dropdown-menu'
import { PopoverContent } from '../popover'
import { TooltipContent } from '../tooltip'
import { SelectContent } from '../select'

describe('floating surfaces keep the page gutter', () => {
  beforeEach(() => {
    for (const k of Object.keys(seen)) delete seen[k]
  })

  it('is the 16 px phone page gutter', () => {
    expect(FLOATING_COLLISION_PADDING).toBe(16)
  })

  it('passes it by default from every kit wrapper', () => {
    render(
      <>
        <DropdownMenuContent />
        <DropdownMenuSubContent />
        <PopoverContent />
        <TooltipContent />
        <SelectContent />
      </>
    )
    expect(seen).toEqual({
      dropdown: 16,
      dropdownSub: 16,
      popover: 16,
      tooltip: 16,
      select: 16,
    })
  })
})
