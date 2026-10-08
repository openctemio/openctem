import { describe, expect, it } from 'vitest'
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import {
  compactCount,
  mapEdgeLabel,
  mapStateTone,
  mapStatus,
  mapSteps,
  nodeBadgeLines,
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
