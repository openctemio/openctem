import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CIABadges, CriticalityBadge, CRITICALITY_LEVEL } from '../classification-badges'
import {
  AssetStatusBadge,
  ASSET_LIFECYCLE_HEALTH,
} from '@/features/asset-lifecycle/components/asset-status-badge'
import { IMPACT_RATING_LEVEL } from '@/lib/impact-colors'

const RAW = /(red|orange|amber|yellow|green|blue|purple|sev|teal)-/

describe('criticality is a Tag level, not a severity hue', () => {
  it.each(Object.entries(CRITICALITY_LEVEL))('%s -> level %i', (value, level) => {
    const { container } = render(
      <CriticalityBadge criticality={value as 'critical'} showTooltip={false} />
    )
    const tag = container.querySelector('[data-slot="tag"]')
    expect(tag).toHaveAttribute('data-level', String(level))
    expect(container.innerHTML).not.toMatch(RAW)
  })

  it('makes only critical bold and gives low one bar (not green)', () => {
    const { container, rerender } = render(<CriticalityBadge criticality="critical" />)
    expect(container.querySelector('[data-slot="tag-label"]')?.className).toContain('font-bold')
    rerender(<CriticalityBadge criticality="low" />)
    expect(container.querySelector('[data-slot="tag"]')).toHaveAttribute('data-level', '1')
    expect(container.innerHTML).not.toMatch(/green/)
  })
})

describe('CIA impact rating is a Tag level', () => {
  it('maps low, moderate, high to 1-3 bars with the dimension letter', () => {
    expect(IMPACT_RATING_LEVEL).toEqual({ low: 1, moderate: 2, high: 3 })
    const { container } = render(
      <CIABadges confidentiality="high" integrity="moderate" availability="low" />
    )
    const levels = [...container.querySelectorAll('[data-slot="tag"]')].map((e) =>
      e.getAttribute('data-level')
    )
    expect(levels).toEqual(['3', '2', '1'])
    expect(container.innerHTML).not.toMatch(RAW)
  })
})

describe('asset lifecycle is a health state', () => {
  it('maps every status', () => {
    expect(ASSET_LIFECYCLE_HEALTH).toEqual({
      active: 'ok',
      stale: 'warn',
      inactive: 'off',
      archived: 'off',
    })
  })
  it('renders stale as warn with its word and days', () => {
    render(<AssetStatusBadge status="stale" daysSinceLastSeen={12} />)
    expect(screen.getByText('Stale')).toBeInTheDocument()
    expect(screen.getByText('12d')).toBeInTheDocument()
  })
})
