import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { FindingDetail } from '../../../types'
import type { FindingTriage } from '../../../hooks/use-finding-triage'
import { showsProofOfFix } from '../../../lib/closure'

vi.mock('@/lib/permissions', () => ({ useCanMutate: () => false }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback?: string, vars?: Record<string, string | number>) =>
      (fallback ?? _k).replace(/\{(\w+)\}/g, (_m, k) => String(vars?.[k] ?? '')),
    locale: 'en',
  }),
}))
vi.mock('@/components/link', () => ({
  default: ({ children, ...p }: { children: React.ReactNode }) => <a {...p}>{children}</a>,
}))
// Neighbouring pieces have their own tests; only the state rows matter here.
vi.mock('../../status-select', () => ({ StatusSelect: () => null }))
vi.mock('../../severity-select', () => ({ SeveritySelect: () => null }))
vi.mock('../../assignee-select', () => ({ AssigneeSelect: () => null }))
vi.mock('../../priority-class-badge', () => ({ PriorityClassBadge: () => null }))
vi.mock('../finding-people', () => ({ FindingPeople: () => null }))
vi.mock('../finding-ticket-links', () => ({ FindingTicketLinks: () => null }))
vi.mock('../severity-provenance', () => ({ SeverityProvenance: () => null }))
vi.mock('../sla-why-this-date', () => ({ SlaWhyThisDate: () => null }))

const { FindingProperties } = await import('../finding-properties')

const DUPLICATE_OF = '0b9c2f7e-3c1a-4c55-9f1e-0d6a1c2b3e4f'

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'Open port',
    description: '',
    severity: 'medium',
    status: 'new',
    source: 'dast',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-05-07T00:00:00Z',
    createdAt: '2026-05-07T00:00:00Z',
    updatedAt: '2026-05-07T00:00:00Z',
    // A deadline that would read as a countdown on an open finding.
    slaDeadline: '2099-01-01T00:00:00Z',
    activities: [],
    ...over,
  } as unknown as FindingDetail
}

function renderState(status: string, over: Partial<FindingDetail> = {}) {
  return render(
    <FindingProperties
      finding={finding({ status: status as FindingDetail['status'], ...over })}
      triage={{ status } as unknown as FindingTriage}
    />
  )
}

/** The value of the property row with this label. */
function rowValue(label: string): HTMLElement {
  const term = screen.getByText(label, { selector: 'dt' })
  return term.closest('[data-slot="property-row"]')?.querySelector('dd') as HTMLElement
}

describe('FindingProperties state row by status', () => {
  it('an open finding shows its SLA countdown', () => {
    renderState('new')
    expect(screen.getByText('SLA due')).toBeInTheDocument()
    expect(screen.queryByText(/Marked false positive|Risk accepted|Resolved/)).toBeNull()
  })

  it('a false positive says so with its date, and has no SLA', () => {
    renderState('false_positive', { resolvedAt: '2026-11-02T10:00:00Z' })
    expect(screen.queryByText('SLA due')).toBeNull()
    expect(screen.queryByText('Resolved')).toBeNull()
    expect(screen.getByText('Marked false positive')).toBeInTheDocument()
    expect(rowValue('Marked false positive')).toHaveTextContent('Nov 2, 2026')
  })

  it('an accepted risk says until when, and when it was accepted', () => {
    renderState('accepted', {
      resolvedAt: '2026-11-02T10:00:00Z',
      acceptanceExpiresAt: '2027-02-01T00:00:00Z',
    })
    expect(screen.queryByText('SLA due')).toBeNull()
    expect(screen.queryByText('Resolved')).toBeNull()
    const value = rowValue('Risk accepted')
    expect(value).toHaveTextContent('Until Feb 1, 2027')
    expect(value).toHaveTextContent('On Nov 2, 2026')
  })

  it('an accepted risk without an end date says it has none', () => {
    renderState('accepted', { resolvedAt: '2026-11-02T10:00:00Z' })
    expect(rowValue('Risk accepted')).toHaveTextContent('No end date')
  })

  it('a duplicate links the finding it duplicates', () => {
    renderState('duplicate', { resolvedAt: '2026-11-02T10:00:00Z', duplicateOf: DUPLICATE_OF })
    expect(screen.queryByText('SLA due')).toBeNull()
    const link = screen.getByRole('link', { name: /The original finding/ })
    expect(link).toHaveAttribute('href', `/findings/${DUPLICATE_OF}`)
    expect(rowValue('Duplicate of')).toHaveTextContent('On Nov 2, 2026')
  })

  it('a resolved finding says Resolved with its date, once', () => {
    renderState('resolved', { resolvedAt: '2026-11-02T10:00:00Z', closureReason: 'fixed' })
    expect(screen.queryByText('SLA due')).toBeNull()
    expect(screen.getAllByText('Resolved')).toHaveLength(1)
    expect(rowValue('Resolved')).toHaveTextContent('Nov 2, 2026')
  })
})

describe('showsProofOfFix', () => {
  it('belongs to open work and to a resolve by a fix only', () => {
    expect(showsProofOfFix('new')).toBe(true)
    expect(showsProofOfFix('in_progress')).toBe(true)
    expect(showsProofOfFix('fix_applied')).toBe(true)
    expect(showsProofOfFix('resolved', 'fixed')).toBe(true)
    expect(showsProofOfFix('resolved', 'mitigated')).toBe(true)
    expect(showsProofOfFix('resolved')).toBe(true)
    expect(showsProofOfFix('resolved', 'obsolete_asset')).toBe(false)
    expect(showsProofOfFix('false_positive', 'detection_error')).toBe(false)
    expect(showsProofOfFix('accepted', 'risk_accepted')).toBe(false)
    expect(showsProofOfFix('duplicate', 'duplicate')).toBe(false)
  })
})
