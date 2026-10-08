import { describe, expect, it } from 'vitest'
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import {
  compactCount,
  mapEdgeLabel,
  mapStateTone,
  mapStatus,
  mapSteps,
  nodeBadgeLines,
  outputsByType,
  outputsDeltaLabel,
  producedNothing,
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
  it('maps every state onto the five WorkflowStages tones', () => {
    expect(
      [
        'pending',
        'waiting',
        'running',
        'succeeded',
        'partial',
        'failed',
        'skipped',
        'canceled',
      ].map(mapStateTone)
    ).toEqual([
      'pending',
      'pending',
      'running',
      'completed',
      'failed',
      'failed',
      'skipped',
      'skipped',
    ])
  })

  it('draws the nodes as workflow steps with their dependencies', () => {
    const steps = mapSteps(map)
    expect(steps.map((s) => s.step_key)).toEqual(['subdomains', 'probe', 'vulns', 'report'])
    expect(steps[1].depends_on).toEqual(['subdomains'])
    expect(steps[2].name).toBe('vulns') // no name: the key
    expect(mapStatus(map)).toMatchObject({
      subdomains: 'completed',
      probe: 'running',
      vulns: 'pending',
    })
    expect(mapSteps(undefined)).toEqual([])
  })

  it('says why a step waits or failed, its chunks and what it produced', () => {
    expect(nodeBadgeLines(map.nodes![0])).toEqual(['Done', '1.2k outputs'])
    expect(nodeBadgeLines(map.nodes![1])).toEqual(['Running', '3/5 chunks, 1 failed'])
    expect(nodeBadgeLines(map.nodes![2])).toEqual(['Waiting for a sensor'])
    expect(nodeBadgeLines(map.nodes![3])).toEqual(['Failed (no sensor available)'])
  })

  it('labels an edge only when the upstream step produced something', () => {
    const label = mapEdgeLabel(map)
    expect(label('subdomains', 'probe')).toBe('1.2k')
    expect(label('probe', 'vulns')).toBeUndefined()
    expect(label('x', 'y')).toBeUndefined()
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
})
