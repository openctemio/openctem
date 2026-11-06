import { describe, expect, it } from 'vitest'
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import {
  compactCount,
  nodeBadgeLines,
  outputsByType,
  outputsDeltaLabel,
  producedNothing,
  producedNothingWhy,
  stepEgressRefused,
  stepGuardRefused,
  stepTasks,
  zeroOutputWarnings,
} from '../run-map'

function node(over: Partial<RunMapNode>): RunMapNode {
  return {
    step_key: 'k',
    depends_on: [],
    state: 'pending',
    findings: 0,
    chunks: { total: 0, queued: 0, running: 0, completed: 0, failed: 0 },
    outputs: { total: 0, by_type: {} },
    ...over,
  } as RunMapNode
}

const map = {
  run_id: 'r',
  status: 'running',
  scan_workflow_version: 3,
  nodes: [
    node({
      step_key: 'subdomains',
      name: 'Subdomains',
      tool: 'subfinder',
      state: 'succeeded',
      outputs: { total: 1240, by_type: { domain: 1240 } },
    }),
    node({
      step_key: 'probe',
      tool: 'httpx',
      depends_on: ['subdomains'],
      state: 'running',
      chunks: { total: 5, queued: 1, running: 1, completed: 2, failed: 1 },
    }),
    node({
      step_key: 'vulns',
      depends_on: ['probe'],
      state: 'waiting',
      reason: 'waiting_for_sensor',
    }),
    node({
      step_key: 'report',
      depends_on: ['vulns'],
      state: 'failed',
      reason: 'NO_SENSOR_AVAILABLE',
    }),
  ],
  edges: [
    { from: 'subdomains', to: 'probe', count: 1240 },
    { from: 'probe', to: 'vulns', count: 0 },
  ],
} as RunMap

describe('run map', () => {
  it('says why a step waits or failed, its chunks and what it produced', () => {
    expect(nodeBadgeLines(map.nodes![0])).toEqual(['Done', '1.2k outputs'])
    expect(nodeBadgeLines(map.nodes![1])).toEqual(['Running', '3/5 chunks, 1 failed'])
    expect(nodeBadgeLines(map.nodes![2])).toEqual(['Waiting for a sensor'])
    expect(nodeBadgeLines(map.nodes![3])).toEqual(['Failed (no sensor available)'])
  })

  it('shortens large counts', () => {
    expect([999, 1000, 1240, 12400, 2_500_000].map(compactCount)).toEqual([
      '999',
      '1k',
      '1.2k',
      '12k',
      '2.5M',
    ])
  })
})

describe('run map step panel helpers', () => {
  it('keeps the tasks of one step', () => {
    const tasks = [
      { id: '1', step_key: 'probe' },
      { id: '2', step_key: 'vulns' },
      { id: '3', step_key: 'probe' },
    ]
    expect(stepTasks(tasks, 'probe').map((t) => t.id)).toEqual(['1', '3'])
    expect(stepTasks(undefined, 'probe')).toEqual([])
  })

  it('lists outputs by type, most first, without empty types', () => {
    const n = node({ outputs: { total: 15, by_type: { ip_address: 3, domain: 12, port: 0 } } })
    expect(outputsByType(n)).toEqual([
      ['domain', 12],
      ['ip_address', 3],
    ])
    expect(outputsByType(undefined)).toEqual([])
  })
})

describe('comparison with the previous run', () => {
  it('says what is new and gone, or that nothing changed', () => {
    const o = (total: number, previous?: number, added = 0, gone = 0) =>
      node({ state: 'succeeded', outputs: { total, by_type: {}, previous, added, gone } })
    expect(outputsDeltaLabel(o(10))).toBeNull() // no previous run
    expect(outputsDeltaLabel(o(10, 8, 3, 1))).toBe('+3 new, 1 gone')
    expect(outputsDeltaLabel(o(8, 8, 0, 0))).toBe('Same as last run')
    expect(outputsDeltaLabel(o(0, 2, 0, 2))).toBe('2 gone')
    expect(outputsDeltaLabel(o(0, 0, 0, 0))).toBeNull()
    expect(nodeBadgeLines(o(10, 8, 3, 1))).toEqual(['Done', '10 outputs', '+3 new, 1 gone'])
  })

  it('says why a step that produced nothing skipped its targets', () => {
    const skipped = (skipped_target_count: number, no_longer_resolve_count = 0) =>
      node({
        step_key: 'rdap',
        name: 'Registration data',
        state: 'succeeded',
        outcome: { skipped_target_count, no_longer_resolve_count },
      } as Partial<RunMapNode>)
    expect(
      zeroOutputWarnings({ nodes: [skipped(376, 376)], edges: [] } as unknown as RunMap)
    ).toEqual([
      {
        key: 'rdap',
        text: 'Registration data produced nothing: all 376 of its targets were refused because the name does not resolve.',
      },
    ])
    expect(producedNothingWhy(skipped(10, 4), 'Registration data')).toBe(
      'Registration data produced nothing: 4 of its 10 skipped targets were refused because the name does not resolve.'
    )
    expect(producedNothingWhy(skipped(3), 'Registration data')).toBe(
      'Registration data produced nothing: 3 of its targets were skipped by the sensor.'
    )
    // Nothing skipped: the plain warning stays.
    expect(producedNothingWhy(node({ state: 'succeeded' }), 'X')).toBeNull()
  })

  it('warns about a finished step that produced nothing', () => {
    const quiet = node({
      step_key: 'ports',
      name: 'Ports',
      state: 'succeeded',
      outputs: { total: 0, by_type: {}, previous: 40, added: 0, gone: 40 },
    })
    const fresh = node({ step_key: 'dns', name: 'DNS', state: 'partial' })
    const found = node({ step_key: 'vulns', state: 'succeeded', findings: 2 })
    const running = node({ step_key: 'probe', state: 'running' })
    expect([quiet, fresh, found, running].map(producedNothing)).toEqual([true, true, false, false])
    expect(nodeBadgeLines(fresh)).toEqual(['Partly done', 'No output'])
    expect(
      zeroOutputWarnings({ nodes: [quiet, fresh, found, running], edges: [] } as unknown as RunMap)
    ).toEqual([
      { key: 'ports', text: 'Ports produced nothing, while the previous run produced 40.' },
      { key: 'dns', text: 'DNS produced nothing.' },
    ])
    expect(zeroOutputWarnings(undefined)).toEqual([])
  })

  it('says a step could not reach its targets when the sensor egress refused them', () => {
    // The live run of 2026-10-14: the port scan finished with nothing
    // because the confined egress refused every connection.
    const ports = node({ step_key: 'ports', name: 'Port scan', state: 'succeeded' })
    const dns = node({ step_key: 'dns', name: 'DNS', state: 'succeeded' })
    const probe = node({ step_key: 'probe', name: 'Probe', state: 'running' })
    const tasks = [
      { step_key: 'ports', egress_refused_targets: 21 },
      { step_key: 'ports', egress_refused_targets: 47 },
      { step_key: 'dns', egress_refused_targets: 1 },
      { step_key: 'probe', egress_refused_targets: 3 },
      { step_key: 'ports' },
      { step_key: 'ports', egress_refused_targets: -4 },
    ]
    expect(stepEgressRefused(tasks, 'ports')).toBe(68)
    expect(stepEgressRefused(undefined, 'ports')).toBe(0)
    expect(
      zeroOutputWarnings(
        { nodes: [ports, dns, probe], edges: [] } as unknown as RunMap,
        undefined,
        tasks
      )
    ).toEqual([
      {
        key: 'ports',
        text: "Port scan could not reach 68 targets (blocked by the sensor's network confinement).",
      },
      {
        key: 'dns',
        text: "DNS could not reach 1 target (blocked by the sensor's network confinement).",
      },
    ])
    // Without the count (an older API), the step produced nothing.
    expect(zeroOutputWarnings({ nodes: [ports], edges: [] } as unknown as RunMap)).toEqual([
      { key: 'ports', text: 'Port scan produced nothing.' },
    ])
  })

  it("says how many of a step's targets the sensor's target guard refused", () => {
    // The live run of 2026-10-14: the HTTP probe was handed host:port
    // targets; one refused target must not read as a failed step.
    const probe = node({
      step_key: 'probe',
      name: 'HTTP probe',
      state: 'succeeded',
      outputs: { total: 4, by_type: {} },
    })
    const ports = node({ step_key: 'ports', name: 'Port scan', state: 'succeeded' })
    const vulns = node({ step_key: 'vulns', name: 'Templates', state: 'running' })
    const tasks = [
      { step_key: 'probe', guard_refused_targets: 2 },
      { step_key: 'probe', guard_refused_targets: 1 },
      { step_key: 'probe', guard_refused_targets: -7 },
      { step_key: 'ports', guard_refused_targets: 1, egress_refused_targets: 5 },
      { step_key: 'vulns', guard_refused_targets: 9 },
    ]
    expect(stepGuardRefused(tasks, 'probe')).toBe(3)
    expect(stepGuardRefused(undefined, 'probe')).toBe(0)
    expect(
      zeroOutputWarnings(
        { nodes: [probe, ports, vulns], edges: [] } as unknown as RunMap,
        undefined,
        tasks
      )
    ).toEqual([
      {
        key: 'probe:guard',
        text: "HTTP probe: 3 targets refused by the sensor's target guard (not run).",
      },
      {
        key: 'ports:guard',
        text: "Port scan: 1 target refused by the sensor's target guard (not run).",
      },
      {
        key: 'ports',
        text: "Port scan could not reach 5 targets (blocked by the sensor's network confinement).",
      },
    ])
  })
})

describe('waiting reasons', () => {
  const chunks = (over: Partial<RunMapNode['chunks']>) =>
    ({ total: 0, queued: 0, running: 0, completed: 0, failed: 0, ...over }) as RunMapNode['chunks']

  it('names the gate when one holds every queued chunk', () => {
    const hosts = node({
      state: 'waiting',
      reason: 'waiting_for_hosts',
      chunks: chunks({ total: 5, queued: 5, hosts_busy: 5 }),
    })
    expect(nodeBadgeLines(hosts)[0]).toBe('Waiting for its hosts: another task is scanning them')
    expect(nodeBadgeLines(hosts).join('\n')).not.toContain('queued:')
    const refused = node({
      state: 'waiting',
      reason: 'waiting_after_refusal',
      chunks: chunks({ total: 4, queued: 4, refused: 4 }),
    })
    expect(nodeBadgeLines(refused)[0]).toBe('Waiting for a sensor whose local policy allows it')
  })

  it('counts each gate when they are mixed', () => {
    const lines = nodeBadgeLines(
      node({
        state: 'waiting',
        reason: 'waiting_for_sensor',
        chunks: chunks({ total: 9, queued: 9, hosts_busy: 5, refused: 4 }),
      })
    )
    expect(lines[0]).toBe('Waiting for a sensor')
    expect(lines).toContain('5 queued: their hosts are being scanned by another task')
    expect(lines).toContain(
      "4 queued: refused by a sensor's local policy, waiting for another sensor"
    )
  })

  it('explains the queued chunks of a running step too', () => {
    const lines = nodeBadgeLines(
      node({ state: 'running', chunks: chunks({ total: 4, queued: 2, running: 2, hosts_busy: 2 }) })
    )
    expect(lines).toContain('2 queued: their hosts are being scanned by another task')
  })
})
