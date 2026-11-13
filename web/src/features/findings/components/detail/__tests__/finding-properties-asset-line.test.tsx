import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import type { FindingDetail } from '../../../types'
import type { FindingTriage } from '../../../hooks/use-finding-triage'

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
// Neighbouring pieces have their own tests; only the asset line matters here.
vi.mock('../../status-select', () => ({ StatusSelect: () => null }))
vi.mock('../../severity-select', () => ({ SeveritySelect: () => null }))
vi.mock('../../assignee-select', () => ({ AssigneeSelect: () => null }))
vi.mock('../../priority-class-badge', () => ({ PriorityClassBadge: () => null }))
vi.mock('../finding-people', () => ({ FindingPeople: () => null }))
vi.mock('../finding-ticket-links', () => ({ FindingTicketLinks: () => null }))
vi.mock('../severity-provenance', () => ({ SeverityProvenance: () => null }))
vi.mock('../sla-why-this-date', () => ({ SlaWhyThisDate: () => null }))

const { FindingProperties } = await import('../finding-properties')

function finding(): FindingDetail {
  return {
    id: 'f1',
    title: 'Open port',
    description: '',
    severity: 'medium',
    status: 'new',
    source: 'dast',
    assets: [
      {
        id: 'a1',
        type: 'ip_address',
        name: '192.0.2.10',
        criticality: 'medium',
        exposure: 'public',
      },
    ],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-05-07T00:00:00Z',
    createdAt: '2026-05-07T00:00:00Z',
    updatedAt: '2026-05-07T00:00:00Z',
    activities: [],
  } as unknown as FindingDetail
}

describe('FindingProperties asset line', () => {
  it('shows type, criticality and exposure as separate pieces, never joined by a middot', () => {
    const { container } = render(
      <FindingProperties
        finding={finding()}
        triage={{ status: 'new' } as unknown as FindingTriage}
      />
    )
    const line = container.querySelector('[data-slot="asset-caption"]') as HTMLElement
    expect(line).not.toBeNull()
    const pieces = Array.from(line.children).map((c) => c.textContent)
    expect(pieces).toEqual(['IP Address', 'Medium criticality', 'Public'])
    expect(line.textContent).not.toContain('·')
  })
})
