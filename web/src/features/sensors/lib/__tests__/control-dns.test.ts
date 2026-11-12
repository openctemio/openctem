import { describe, expect, it } from 'vitest'

import type { SensorConfigReport } from '@/lib/api/sensor-types'

import { controlDnsFact, observedValueText, withControlDnsReason } from '../control-dns'
import type { HealthIssue } from '../health-issues'

function report(code: string, observed: Record<string, string>): SensorConfigReport {
  return {
    state: 'reported',
    stale: false,
    health: 'attention',
    truncated: false,
    checks: [
      {
        id: 'runtime.control_dns',
        group: 'runtime',
        status: 'warn',
        severity: 'warning',
        code,
        known: true,
        title: 'x',
        observed: Object.entries(observed).map(([label, value]) => ({ label, value })),
      },
    ],
  }
}

const offline: HealthIssue = {
  key: 'heartbeat',
  severity: 'critical',
  title: 'Offline',
  text: 'No heartbeat for 2 h.',
  since: '2026-11-06T08:00:00.000Z',
}

describe('controlDnsFact', () => {
  it('reads a lookup failure with its cause and start', () => {
    const f = controlDnsFact(
      report('lookup_failed', { cause: 'server_misbehaving', since: '1793001600', host: 'p' })
    )
    expect(f).toEqual({
      kind: 'failing',
      cached: false,
      cause: 'server_misbehaving',
      since: new Date(1793001600 * 1000),
    })
  })

  it('drops a cause outside the closed set and a non-numeric time', () => {
    const f = controlDnsFact(report('cached_address', { cause: '<b>x</b>', since: 'soon' }))
    expect(f).toEqual({ kind: 'failing', cached: true, cause: undefined, since: undefined })
  })

  it('reads a recovered outage and nothing for a resolving host', () => {
    expect(
      controlDnsFact(report('recovered', { failed_at: '1793001600', recovered_at: '1793005200' }))
    ).toEqual({
      kind: 'recovered',
      failedAt: new Date(1793001600 * 1000),
      recoveredAt: new Date(1793005200 * 1000),
    })
    expect(controlDnsFact(report('resolving', {}))).toBeNull()
    expect(controlDnsFact(undefined)).toBeNull()
  })
})

describe('withControlDnsReason', () => {
  it('names the DNS failure as the offline reason', () => {
    const f = controlDnsFact(report('lookup_failed', { cause: 'timeout', since: '1793001600' }))
    const [out] = withControlDnsReason([offline], f)
    expect(out.title).toBe('Offline: DNS failure')
    expect(out.text).toContain('the resolver did not answer')
    expect(out.since).toBe(new Date(1793001600 * 1000).toISOString())
  })

  it('leaves the issues alone without a reported failure', () => {
    expect(withControlDnsReason([offline], null)).toEqual([offline])
    const rec = controlDnsFact(report('recovered', {}))
    expect(withControlDnsReason([offline], rec)).toEqual([offline])
  })
})

describe('observedValueText', () => {
  it('shows the DNS check times as dates and leaves the rest', () => {
    expect(observedValueText('runtime.control_dns', 'since', '1793001600')).toBe(
      new Date(1793001600 * 1000).toLocaleString()
    )
    expect(observedValueText('runtime.control_dns', 'host', 'platform.example.com')).toBe(
      'platform.example.com'
    )
    expect(observedValueText('tool.nuclei.binary', 'since', '1793001600')).toBe('1793001600')
  })
})
