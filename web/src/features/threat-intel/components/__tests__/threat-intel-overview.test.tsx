import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { ThreatIntelOverview } from '../threat-intel-stats'

const epss = { total_scores: 394588, high_risk_count: 12, critical_risk_count: 3 }
const kev = {
  total_entries: 1754,
  past_due_count: 2,
  recently_added_last_30_days: 33,
  ransomware_related_count: 361,
  tenant_open_count: 5,
  tenant_ransomware_open_count: 1,
  tenant_new_kev_matches_30d: 4,
}

describe('ThreatIntelOverview', () => {
  it('shows the organization figures with the thresholds the API counts at', () => {
    render(<ThreatIntelOverview epssStats={epss} kevStats={kev} />)
    expect(screen.getByText('EPSS 50% or more')).toBeInTheDocument()
    expect(screen.getByText('EPSS 10% or more')).toBeInTheDocument()
    // The old 30% label described a threshold the API never used.
    expect(screen.queryByText(/30%/)).not.toBeInTheDocument()
    // No ratio of the organization's findings to the global catalog.
    expect(screen.queryByText(/high-risk rate/i)).not.toBeInTheDocument()
  })

  it('keeps catalog sizes out of the organization strip', () => {
    render(<ThreatIntelOverview epssStats={epss} kevStats={kev} />)
    const catalogs = screen.getByRole('region', { name: 'Catalogs' })
    expect(within(catalogs).getByText(/394,588 CVEs scored/)).toBeInTheDocument()
    expect(within(catalogs).getByText(/1,754 entries, 33 added/)).toBeInTheDocument()
    // KEV "on track" used to be the catalog size minus the organization's past-due count.
    expect(screen.queryByText(/on track/i)).not.toBeInTheDocument()
  })

  it('opens the findings list each number counts', () => {
    render(<ThreatIntelOverview epssStats={epss} kevStats={kev} />)
    // Real links (open in a new tab, show the URL), not buttons that navigate.
    const href = (name: RegExp) => screen.getByRole('link', { name }).getAttribute('href')
    expect(href(/EPSS 50% or more/)).toBe('/findings?epss_score_gte=0.5')
    expect(href(/EPSS 10% or more/)).toBe('/findings?epss_score_gte=0.1')
    expect(href(/In CISA KEV/)).toBe('/findings?is_in_kev=true')
    expect(screen.queryByRole('button', { name: /EPSS 50% or more/ })).toBeNull()
  })
})
