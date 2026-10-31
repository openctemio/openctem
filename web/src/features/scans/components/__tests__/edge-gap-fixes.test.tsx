/**
 * The fix links of a host an edge protection stopped or that kept rate
 * limiting the scan: one shared component, used by the run page and the
 * asset coverage section.
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

import { EdgeGapFixes } from '../edge-gap-fixes'
import { gapEdgeKind, gapsFixKind, outcomeEdgeKind } from '../../lib/edge-gap'
import { gapHelp } from '../../lib/placement-help'

const hrefs = () => screen.getAllByRole('link').map((a) => a.getAttribute('href'))

describe('EdgeGapFixes', () => {
  it('offers the three fixes for an edge block or challenge', () => {
    for (const kind of ['edge_blocked', 'edge_challenged'] as const) {
      const { unmount } = render(<EdgeGapFixes kind={kind} />)
      expect(screen.getByText('How to fix')).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Allow our scanner addresses' })).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Use another proxy pool' })).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Lower the scan rate' })).toBeInTheDocument()
      expect(hrefs()).toEqual([
        '/settings/scanning/proxies#scanner-addresses',
        '/settings/scanning/proxies',
        '/settings/scanning/tool-defaults',
      ])
      unmount()
    }
  })

  it('offers the rate and the proxy fixes for a rate limit', () => {
    render(<EdgeGapFixes kind="rate_limited" />)
    expect(hrefs()).toEqual(['/settings/scanning/tool-defaults', '/settings/scanning/proxies'])
  })
})

describe('edge gap kinds', () => {
  it('maps a gap to its kind; other reasons have no fix', () => {
    expect(gapEdgeKind({ reason: 'blocked', edge: 'challenged' })).toBe('edge_challenged')
    expect(gapEdgeKind({ reason: 'blocked', edge: 'blocked' })).toBe('edge_blocked')
    expect(gapEdgeKind({ reason: 'blocked' })).toBe('edge_blocked')
    expect(gapEdgeKind({ reason: 'rate_floor' })).toBe('rate_limited')
    expect(gapEdgeKind({ reason: 'breaker_open' })).toBeNull()
    expect(gapEdgeKind({ reason: 'proxy_unavailable' })).toBeNull()
  })

  it('offers one set of fixes per task, the edge fixes first', () => {
    expect(gapsFixKind([{ reason: 'rate_floor' }, { reason: 'blocked', edge: 'blocked' }])).toBe(
      'edge_blocked'
    )
    expect(gapsFixKind([{ reason: 'rate_floor' }])).toBe('rate_limited')
    expect(gapsFixKind([{ reason: 'breaker_open' }])).toBeNull()
    expect(gapsFixKind([])).toBeNull()
  })

  it('maps a ledger outcome to its kind', () => {
    expect(outcomeEdgeKind('edge_challenged')).toBe('edge_challenged')
    expect(outcomeEdgeKind('rate_limited')).toBe('rate_limited')
    expect(outcomeEdgeKind('unreachable')).toBeNull()
    expect(outcomeEdgeKind(undefined)).toBeNull()
  })

  it('names the vendor as sent, never a fixed one', () => {
    expect(gapHelp({ reason: 'blocked', edge: 'blocked', vendor: 'datadome' }).label).toBe(
      'blocked by edge protection (datadome)'
    )
    expect(gapHelp({ reason: 'blocked', edge: 'challenged' }).label).toBe(
      'challenged by edge protection'
    )
    expect(gapHelp({ reason: 'rate_floor' }).label).toBe('kept rate-limiting the scan')
  })
})
