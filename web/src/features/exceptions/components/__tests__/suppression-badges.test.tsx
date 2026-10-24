import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { SuppressionStatusBadge, SuppressionTypeBadge } from '../suppression-badges'

describe('suppression badges', () => {
  it('renders the approval status as a lozenge with its tone', () => {
    const { container } = render(<SuppressionStatusBadge status="pending" />)
    const el = container.querySelector('[data-slot="status-lozenge"]')
    expect(el?.getAttribute('data-tone')).toBe('waiting')
    expect(el?.textContent).toBeTruthy()
  })

  it('renders accepted risk as a plain tag, not a violet badge', () => {
    const { container } = render(<SuppressionTypeBadge type="accepted_risk" />)
    expect(container.querySelector('[data-slot="tag"][data-variant="plain"]')).toBeTruthy()
    expect(container.innerHTML).not.toMatch(/purple|violet|prio/)
  })
})
