import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Button, buttonVariants } from '../button'

describe('Button variant signal', () => {
  it('is the teal-filled main action with the live shape, shadow and hover', () => {
    render(<Button variant="signal">Create scan</Button>)
    const cls = screen.getByRole('button', { name: 'Create scan' }).className
    expect(cls).toContain('bg-signal')
    expect(cls).toContain('text-signal-ink')
    expect(cls).toContain('shadow-xs')
    expect(cls).toContain('hover:bg-signal/90')
    // Same base as every variant: height, radius and focus ring come from the kit.
    expect(cls).toContain('rounded-md')
    expect(cls).toContain('focus-visible:ring-[3px]')
  })

  it('leaves the other variants untouched', () => {
    expect(buttonVariants({ variant: 'default' })).toContain('bg-primary')
    expect(buttonVariants({ variant: 'default' })).not.toContain('bg-signal')
    expect(buttonVariants({ variant: 'destructive' })).not.toContain('bg-signal')
    expect(buttonVariants({ variant: 'outline' })).not.toContain('bg-signal')
  })
})
