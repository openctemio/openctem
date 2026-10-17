import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ClassificationBadges } from '../classification-badges'
import type { AssetAttribution } from '../../lib/attribution'

const attributionMock = vi.hoisted(() => ({
  calls: [] as (string | null)[],
  value: undefined as AssetAttribution | undefined,
}))

vi.mock('../../hooks/use-asset-attribution', () => ({
  useAssetAttribution: (id: string | null) => {
    attributionMock.calls.push(id)
    return { attribution: id ? attributionMock.value : undefined }
  },
}))

import { AssetScopeChip, triageFromAttribution } from '../asset-scope-chip'

function attribution(overrides: Partial<AssetAttribution>): AssetAttribution {
  return {
    state: 'confirmed',
    confidence: 80,
    recorded: true,
    human_decided: false,
    active_checks_allowed: true,
    evidence: [],
    ...overrides,
  }
}

describe('ClassificationBadges, labelled (asset header)', () => {
  it('names each value and puts a set zone last', () => {
    const { container } = render(
      <ClassificationBadges scope="cloud" exposure="public" criticality="medium" labelled />
    )
    const text = container.textContent ?? ''
    expect(text).toContain('Criticality:')
    expect(text).toContain('Exposure:')
    expect(text).toContain('Zone:')
    expect(text.indexOf('Criticality:')).toBeLessThan(text.indexOf('Exposure:'))
    expect(text.indexOf('Exposure:')).toBeLessThan(text.indexOf('Zone:'))
    expect(screen.getByText('Public')).toBeInTheDocument()
  })

  it('hides the default zone, so a public website never reads "Zone: Internal"', () => {
    const { container } = render(
      <ClassificationBadges scope="internal" exposure="public" criticality="medium" labelled />
    )
    expect(container.textContent).not.toContain('Zone:')
    expect(screen.queryByText('Internal')).not.toBeInTheDocument()
  })

  it('stays compact without labels (lists)', () => {
    const { container } = render(
      <ClassificationBadges scope="internal" exposure="public" criticality="medium" />
    )
    expect(container.textContent).not.toContain('Zone:')
  })
})

describe('AssetScopeChip', () => {
  beforeEach(() => {
    attributionMock.calls = []
    attributionMock.value = undefined
  })

  it('uses the list row triage and does not fetch', () => {
    render(
      <AssetScopeChip
        asset={{
          id: 'a1',
          triage: {
            attributionState: 'confirmed',
            confidence: 100,
            humanDecided: false,
            scanAllowed: true,
          },
        }}
      />
    )
    expect(screen.getByText('In scope')).toBeInTheDocument()
    expect(attributionMock.calls.every((id) => id === null)).toBe(true)
  })

  it('without row triage, reads the attribution: passive only for a discovered, uncovered asset', () => {
    attributionMock.value = attribution({
      state: 'discovered',
      active_checks_allowed: false,
      active_checks_blocked_by: 'discovered',
      blocked_code: 'no_entry',
    })
    render(<AssetScopeChip asset={{ id: 'a2' }} />)
    expect(attributionMock.calls).toContain('a2')
    expect(screen.getByText('Not in scope · passive only')).toBeInTheDocument()
  })

  it('an excluded asset reads Excluded', () => {
    attributionMock.value = attribution({ active_checks_allowed: false, blocked_code: 'excluded' })
    render(<AssetScopeChip asset={{ id: 'a3' }} />)
    expect(screen.getByText('Excluded')).toBeInTheDocument()
  })

  it('renders nothing until the answer is known (no guess)', () => {
    const { container } = render(<AssetScopeChip asset={{ id: 'a4' }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('maps a blocked answer without a code to "no entry"', () => {
    expect(
      triageFromAttribution(attribution({ active_checks_allowed: false })).scanRefusalCode
    ).toBe('no_entry')
    expect(triageFromAttribution(attribution({})).scanRefusalCode).toBeUndefined()
  })
})
