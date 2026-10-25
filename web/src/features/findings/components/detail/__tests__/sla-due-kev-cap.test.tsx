import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { SlaDue } from '../finding-properties'

const deadline = '2999-01-01T00:00:00Z'

describe('SlaDue: known exploited deadline cap', () => {
  it('says why the deadline is shorter when the KEV cap set it', () => {
    const { container } = render(<SlaDue deadline={deadline} status="on_track" kevCapped />)
    const reason = container.querySelector('[data-slot="sla-kev-capped"]')
    expect(reason?.textContent).toBe('Shortened because it is in CISA KEV')
  })

  it('says nothing when the class or severity window set it', () => {
    const { container } = render(<SlaDue deadline={deadline} status="on_track" />)
    expect(container.querySelector('[data-slot="sla-kev-capped"]')).toBeNull()
  })
})
