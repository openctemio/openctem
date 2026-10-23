/**
 * The threat intelligence strip: at most five tiles, each a link to the
 * findings list it filters, with the catalogue counts and no corner icons.
 */

import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ThreatIntelStrip } from '../threat-intel-stats'
import type { EPSSStats, KEVStats } from '@/lib/api/threatintel-types'

const epss = { total_scores: 250000, critical_risk_count: 4200, high_risk_count: 9100 } as EPSSStats
const kev = { total_entries: 1500, past_due_count: 3 } as KEVStats

describe('ThreatIntelStrip', () => {
  it('shows one linked tile per list, with its count', () => {
    render(<ThreatIntelStrip epssStats={epss} kevStats={kev} />)
    const links = screen.getAllByRole('link')
    expect(links.length).toBeLessThanOrEqual(5)
    expect(links.map((a) => a.getAttribute('href'))).toEqual([
      '/findings?epss_score_gte=0.3',
      '/findings?epss_score_gte=0.1',
      '/findings?is_in_kev=true',
    ])
    expect(screen.getByText('4,200')).toBeTruthy()
    expect(screen.getByText('9,100')).toBeTruthy()
    expect(screen.getByText('1,500')).toBeTruthy()
    expect(document.querySelectorAll('svg').length).toBe(0)
  })

  it('shows skeletons, not zeros, until the stats arrive', () => {
    render(<ThreatIntelStrip isLoading />)
    expect(screen.queryByText('0')).toBeNull()
  })
})
