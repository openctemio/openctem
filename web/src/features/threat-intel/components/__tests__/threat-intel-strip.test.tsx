/**
 * The threat intelligence headline: catalogue facts on one line, not metric
 * tiles (they count the EPSS and KEV catalogues, which no list here shows).
 */

import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ThreatIntelStrip } from '../threat-intel-stats'
import type { EPSSStats, KEVStats } from '@/lib/api/threatintel-types'

const epss = { total_scores: 250000, critical_risk_count: 4200, high_risk_count: 9100 } as EPSSStats
const kev = { total_entries: 1500, past_due_count: 3 } as KEVStats

describe('ThreatIntelStrip', () => {
  it('shows the catalogue counts as one metadata line with no links or tiles', () => {
    render(<ThreatIntelStrip epssStats={epss} kevStats={kev} />)
    expect(screen.getByText('4,200')).toBeTruthy()
    expect(screen.getByText('9,100')).toBeTruthy()
    expect(screen.getByText('1,500')).toBeTruthy()
    expect(screen.queryAllByRole('link')).toHaveLength(0)
    expect(document.querySelector('[data-slot=metric-strip]')).toBeNull()
    expect(document.querySelector('[data-slot=meta-line]')).not.toBeNull()
  })

  it('shows a skeleton, not zeros, until the stats arrive', () => {
    render(<ThreatIntelStrip isLoading />)
    expect(screen.queryByText('0')).toBeNull()
  })
})
