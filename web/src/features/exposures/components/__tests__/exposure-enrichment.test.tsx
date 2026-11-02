/**
 * ExposureThreatPills / ExposureSecurityContext tests.
 *
 * Verifies that read-time CTEM enrichment (api #483) is surfaced ONLY when the
 * API returns each field — never as an empty default — and that the compact list
 * and detail presentations stay in sync with the data contract.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import * as React from 'react'
import type { ExposureEvent } from '@/lib/api/exposure-types'

// Simplify tooltip rendering so trigger content is always in the DOM.
vi.mock('@/components/ui/tooltip', () => ({
  Tooltip: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
  TooltipContent: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
  TooltipProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement('div', null, children),
  TooltipTrigger: (() => {
    const Trigger = React.forwardRef<
      HTMLDivElement,
      { children: React.ReactNode; asChild?: boolean }
    >(({ children, ...props }, ref) => React.createElement('div', { ...props, ref }, children))
    Trigger.displayName = 'TooltipTrigger'
    return Trigger
  })(),
}))

function makeExposure(overrides: Partial<ExposureEvent> = {}): ExposureEvent {
  return {
    id: 'exp-1',
    event_type: 'port_open',
    severity: 'high',
    state: 'active',
    title: 'Open port 22',
    fingerprint: 'fp',
    source: 'scanner',
    first_seen_at: '2026-08-01T00:00:00Z',
    last_seen_at: '2026-08-01T00:00:00Z',
    created_at: '2026-08-01T00:00:00Z',
    updated_at: '2026-08-01T00:00:00Z',
    ...overrides,
  }
}

describe('hasExposureEnrichment', () => {
  it('is false for a bare exposure with no CTEM signals', async () => {
    const { hasExposureEnrichment } = await import('../exposure-enrichment')
    expect(hasExposureEnrichment(makeExposure())).toBe(false)
  })

  it('is true when any single signal is present', async () => {
    const { hasExposureEnrichment } = await import('../exposure-enrichment')
    expect(hasExposureEnrichment(makeExposure({ is_in_kev: true }))).toBe(true)
    expect(hasExposureEnrichment(makeExposure({ epss_score: 0.4 }))).toBe(true)
    expect(hasExposureEnrichment(makeExposure({ on_attack_path: true }))).toBe(true)
    expect(hasExposureEnrichment(makeExposure({ effective_criticality: 'critical' }))).toBe(true)
  })

  it('ignores an EPSS score of zero and an unknown criticality', async () => {
    const { hasExposureEnrichment } = await import('../exposure-enrichment')
    expect(hasExposureEnrichment(makeExposure({ epss_score: 0 }))).toBe(false)
    expect(hasExposureEnrichment(makeExposure({ effective_criticality: 'bogus' }))).toBe(false)
  })
})

describe('ExposureThreatPills', () => {
  it('renders nothing when there is no enrichment', async () => {
    const { ExposureThreatPills } = await import('../exposure-enrichment')
    const { container } = render(<ExposureThreatPills exposure={makeExposure()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders KEV, EPSS and effective-criticality pills when present', async () => {
    const { ExposureThreatPills } = await import('../exposure-enrichment')
    render(
      <ExposureThreatPills
        exposure={makeExposure({
          is_in_kev: true,
          epss_score: 0.123,
          effective_criticality: 'critical',
        })}
      />
    )
    expect(screen.getByText('KEV')).toBeInTheDocument()
    expect(screen.getByText('EPSS 12.3%')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('collapses reachability to the attack-path pill when on a path', async () => {
    const { ExposureThreatPills } = await import('../exposure-enrichment')
    render(
      <ExposureThreatPills
        exposure={makeExposure({ on_attack_path: true, is_internet_accessible: true })}
      />
    )
    expect(screen.getByText('Attack path')).toBeInTheDocument()
    expect(screen.queryByText('Internet-facing')).not.toBeInTheDocument()
  })

  it('shows the internet-facing pill when reachable but not on a path', async () => {
    const { ExposureThreatPills } = await import('../exposure-enrichment')
    render(
      <ExposureThreatPills
        exposure={makeExposure({ on_attack_path: false, is_internet_accessible: true })}
      />
    )
    expect(screen.getByText('Internet-facing')).toBeInTheDocument()
  })
})

describe('ExposureSecurityContext', () => {
  it('renders nothing when there is no enrichment', async () => {
    const { ExposureSecurityContext } = await import('../exposure-enrichment')
    const { container } = render(<ExposureSecurityContext exposure={makeExposure()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the section with KEV due date and EPSS percentile when present', async () => {
    const { ExposureSecurityContext } = await import('../exposure-enrichment')
    render(
      <ExposureSecurityContext
        exposure={makeExposure({
          is_in_kev: true,
          kev_due_date: '2026-09-01T00:00:00Z',
          epss_score: 0.5,
          // The API serves the percentile on the canonical 0–100 scale.
          epss_percentile: 97.4,
          cve_id: 'CVE-2026-1234',
        })}
      />
    )
    expect(screen.getByText('Security context')).toBeInTheDocument()
    expect(screen.getByText('Known exploited')).toBeInTheDocument()
    expect(screen.getByText('EPSS')).toBeInTheDocument()
    expect(screen.getByText(/97th pct/)).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument()
  })

  it('does not rescale a 0–100 percentile (it used to render 9990th)', async () => {
    const { ExposureSecurityContext } = await import('../exposure-enrichment')
    render(
      <ExposureSecurityContext
        exposure={makeExposure({
          epss_score: 0.97565,
          epss_percentile: 99.9,
          cve_id: 'CVE-2021-44228',
        })}
      />
    )
    expect(screen.getByText(/99th pct/)).toBeInTheDocument()
    expect(screen.queryByText(/9990/)).not.toBeInTheDocument()
  })
})

describe('CTEM-ID row', () => {
  const ctem = {
    code: 'CTEM-DOM-2',
    catalog_version: '1.0',
    basis: 'lookalike_technique',
    url: 'https://ctem.org/docs/ctem-dom-2',
  }

  it('counts as enrichment and links the code to its ctem.org page', async () => {
    const { ExposureSecurityContext, hasExposureEnrichment } =
      await import('../exposure-enrichment')
    const exposure = makeExposure({ event_type: 'lookalike_domain', ctem_id: ctem })
    expect(hasExposureEnrichment(exposure)).toBe(true)
    render(<ExposureSecurityContext exposure={exposure} />)
    const link = screen.getByRole('link', { name: /CTEM-DOM-2/ })
    expect(link).toHaveAttribute('href', 'https://ctem.org/docs/ctem-dom-2')
    expect(link).toHaveAttribute('target', '_blank')
    expect(screen.getByText('Lookalike domain using look-alike characters')).toBeInTheDocument()
    expect(screen.getByText('Chosen from how the lookalike was generated')).toBeInTheDocument()
  })

  it('renders the code as text when the link is not http(s)', async () => {
    const { ExposureSecurityContext } = await import('../exposure-enrichment')
    render(
      <ExposureSecurityContext
        exposure={makeExposure({ ctem_id: { ...ctem, url: 'javascript:alert(1)' } })}
      />
    )
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
    expect(screen.getByText('CTEM-DOM-2')).toBeInTheDocument()
  })
})

describe('CTEM-ID labels', () => {
  // The codes the API can derive today (api/pkg/domain/ctemid/mapping.go).
  const derivable = [
    'CTEM-DOM-1',
    'CTEM-DOM-2',
    'CTEM-CRD-1',
    'CTEM-CRD-2',
    'CTEM-EXP-3',
    'CTEM-EXP-4',
    'CTEM-EXP-5',
    'CTEM-EXP-6',
    'CTEM-SRC-3',
  ]
  const bases = ['lookalike_technique', 'credential_dump', 'asset_scope', 'asset_type']

  it.each(['en', 'vi'])('%s has a label for every derivable code and basis', async (lang) => {
    const dict = (await import(`@/lib/i18n/dictionaries/${lang}/exposures.json`)).default as Record<
      string,
      string
    >
    for (const code of derivable) expect(dict[`exposures.ctemId.code.${code}`]).toBeTruthy()
    for (const b of bases) expect(dict[`exposures.ctemId.basis.${b}`]).toBeTruthy()
  })
})
