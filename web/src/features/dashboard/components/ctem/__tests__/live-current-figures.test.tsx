import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { PriorityOverTime } from '../priority-over-time'
import { ExposureHero, p0Series } from '../exposure-hero'
import { FixNextQueue, orderFixNext } from '../fix-next-queue'
import { CtemLoop } from '../ctem-loop'
import { CoverageHygiene } from '../coverage-hygiene'
import type {
  ExecTopRisk,
  ExecutiveSummary,
  RiskTrendPoint,
} from '../../../hooks/use-ctem-dashboard'

vi.mock('next/dynamic', () => ({ default: () => () => null }))

// research/188 A-002, A-003, A-004, A-007: "current" figures are live counts
// in the viewer's scope, a failed read is an error and never 0, an
// unmeasurable figure is "—", and Fix next follows the priority class.

const summary: ExecutiveSummary = {
  risk_score_current: 46,
  risk_score_change: 0,
  p0_open: 1,
  p0_resolved_period: 0,
  p1_open: 12,
  p2_open: 20,
  p3_open: 14,
  sla_compliance_pct: 52,
  sla_breached: 20,
  mttr_critical_hours: null,
  crown_jewels_at_risk: 3,
  findings_total: 47,
  findings_resolved_period: 5,
  top_risks: [],
}

// Yesterday's org-wide snapshot: 5 P0, 6 P1. Never shown as "current".
const trend: RiskTrendPoint[] = [
  {
    date: '2026-10-16',
    risk_score_avg: 40,
    findings_open: 40,
    sla_compliance_pct: 50,
    p0_open: 4,
    p1_open: 6,
    p2_open: 14,
    p3_open: 16,
  },
  {
    date: '2026-10-17',
    risk_score_avg: 41,
    findings_open: 45,
    sla_compliance_pct: 50,
    p0_open: 5,
    p1_open: 6,
    p2_open: 14,
    p3_open: 18,
  },
]

function bar(cls: string) {
  return screen.getByRole('link', { name: new RegExp(`^Open ${cls} findings`) })
}

describe('PriorityOverTime current bars', () => {
  it('shows the live open counts, not the last snapshot, each linking to its list', () => {
    render(<PriorityOverTime summary={summary} trend={trend} />)
    expect(within(bar('P0')).getByText('1')).toBeInTheDocument()
    expect(within(bar('P1')).getByText('12')).toBeInTheDocument()
    expect(within(bar('P2')).getByText('20')).toBeInTheDocument()
    expect(within(bar('P3')).getByText('14')).toBeInTheDocument()
    expect(bar('P1')).toHaveAttribute('href', '/findings?state=open&priority_class=P1')
    expect(screen.getByText(/History from daily snapshots/)).toBeInTheDocument()
  })

  it('gives a scoped viewer their own live counts and no organization trend', () => {
    render(
      <PriorityOverTime summary={{ ...summary, p0_open: 0, p1_open: 3, scoped: true }} trend={[]} />
    )
    expect(within(bar('P1')).getByText('3')).toBeInTheDocument()
    expect(screen.getByText('Trend not available for your scope')).toBeInTheDocument()
    expect(screen.queryByText('No trend data yet')).toBeNull()
  })

  it('shows an error, not zeros, when the summary read fails', () => {
    render(
      <PriorityOverTime summaryError={new Error('500')} trend={trend} onRetrySummary={vi.fn()} />
    )
    expect(screen.getByRole('alert')).toHaveTextContent("Couldn't load these figures")
    expect(screen.queryByRole('link', { name: /^Open P0 findings/ })).toBeNull()
  })
})

describe('ExposureHero', () => {
  it('ends the P0 line at the live count', () => {
    expect(p0Series(trend, 1, '2026-10-18').map((p) => p.p0)).toEqual([4, 5, 1])
    // A snapshot already taken today is replaced, not duplicated.
    expect(p0Series(trend, 1, '2026-10-17').map((p) => p.p0)).toEqual([4, 1])
  })

  it('says gaining ground when today is below the start, whatever yesterday said', () => {
    render(<ExposureHero summary={summary} trend={trend} kevChainCount={0} />)
    expect(screen.getByText(/gaining ground/i)).toBeInTheDocument()
  })

  it('shows an error instead of "0 P0" when the read fails', () => {
    render(<ExposureHero error={new Error('500')} trend={trend} kevChainCount={0} />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.queryByText('P0')).toBeNull()
  })
})

describe('CtemLoop and coverage', () => {
  it('shows "—" with the reason for a failed read and for nothing to measure', () => {
    render(
      <CtemLoop
        summary={summary}
        scanCoverage={{
          coverage_percent: 0,
          total_scannable: 0,
          never_scanned: 0,
          critical_uncovered: 0,
        }}
        errors={{ validation: new Error('500') }}
      />
    )
    expect(screen.getByText('No scannable assets in your scope')).toBeInTheDocument()
    expect(screen.getByText("Couldn't load these figures")).toBeInTheDocument()
    expect(screen.queryByText(/0 of 0 validated/)).toBeNull()
  })

  it('does not call coverage 0 % when there is nothing scannable', () => {
    render(
      <CoverageHygiene
        scan={{ coverage_percent: 0, total_scannable: 0, never_scanned: 0, critical_uncovered: 0 }}
        validation={{ overall_pct: 0, validated: 0, total: 0 }}
        slaPct={null}
      />
    )
    expect(screen.queryByText('0%')).toBeNull()
    expect(screen.getAllByText('—')).toHaveLength(3)
  })
})

describe('Fix next order', () => {
  const risk = (title: string, cls: string, epss?: number): ExecTopRisk => ({
    title,
    severity: 'high',
    priority_class: cls,
    asset_name: 'a',
    epss_score: epss,
    is_in_kev: false,
  })

  it('puts a P0 without EPSS above a P1 with EPSS 1.0, and chains after findings', () => {
    const order = orderFixNext(
      [
        {
          entry_point_name: 'edge',
          target_name: 'db',
          hops: [],
          kev_count: 1,
          score: 100,
          is_crown_jewel: true,
        },
      ],
      [risk('p1 high epss', 'P1', 1), risk('leaked key', 'P0'), risk('p2', 'P2', 0.9)]
    ).map((i) => i.title)
    expect(order).toEqual(['leaked key', 'p1 high epss', 'p2', 'db — via edge'])
  })

  it('shows an error instead of "nothing exploitable" when the read fails', () => {
    render(<FixNextQueue error={new Error('500')} chains={[]} />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.queryByText(/Nothing exploitable/)).toBeNull()
  })
})
