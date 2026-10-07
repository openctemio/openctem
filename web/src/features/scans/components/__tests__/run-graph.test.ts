import { describe, expect, it } from 'vitest'

import { layeredLayout } from '@/components/flow/layered-layout'
import type { StepRun } from '@/lib/api'
import type { RunStage } from '@/lib/api/generated'
import { runGraphModel, statusTone } from '../run-graph'

function sr(key: string, status: StepRun['status'], over: Partial<StepRun> = {}): StepRun {
  return {
    id: `sr-${key}`,
    step_key: key,
    status,
    findings_count: 0,
    attempt: 1,
    max_attempts: 1,
    ...over,
  }
}

describe('runGraphModel', () => {
  it('builds one node per step run with its lane counts, from the API only', () => {
    const lanes: RunStage[] = [
      {
        stage_key: 'ports',
        stage: 'scan.ports',
        inputs: 7,
        planned: 3,
        skipped: { unconfirmed: 2 },
      },
    ]
    const { nodes, edges } = runGraphModel(
      [
        sr('subs', 'completed', {
          step_name: 'Subdomains',
          tool: 'subfinder',
          capability: 'discover.subdomains@1',
        }),
        sr('ports', 'running', { tool: 'naabu', capability: 'scan.ports@1', findings_count: 0 }),
        sr('vulns', 'failed', { error_message: 'boom', findings_count: 4 }),
      ],
      lanes,
      { ports: ['subs'], vulns: ['ports', 'removed-step'] }
    )
    expect(nodes.map((n) => n.key)).toEqual(['subs', 'ports', 'vulns'])
    expect(nodes[0]).toMatchObject({
      name: 'Subdomains',
      tool: 'subfinder',
      capability: 'discover.subdomains@1',
    })
    expect(nodes[1].lane).toMatchObject({ inputs: 7, planned: 3 })
    expect(nodes[2]).toMatchObject({ status: 'failed', error: 'boom', findings: 4 })
    // An edge to a step that is not in the run is dropped.
    expect(edges).toEqual([
      { source: 'subs', target: 'ports' },
      { source: 'ports', target: 'vulns' },
    ])
  })

  it('maps statuses to tones', () => {
    expect(statusTone('completed')).toBe('ok')
    expect(statusTone('running')).toBe('run')
    expect(statusTone('failed')).toBe('bad')
    expect(statusTone('skipped')).toBe('idle')
  })
})

describe('layeredLayout', () => {
  it('places each node at its longest path from a root', () => {
    const pos = layeredLayout(
      ['a', 'b', 'c', 'd'],
      [
        { source: 'a', target: 'b' },
        { source: 'b', target: 'c' },
        { source: 'a', target: 'c' },
        { source: 'a', target: 'd' },
      ]
    )
    expect(pos.a.x).toBe(0)
    expect(pos.b.x).toBe(300)
    expect(pos.c.x).toBe(600)
    expect(pos.d.x).toBe(300)
    expect(pos.d.y).not.toBe(pos.b.y)
  })

  it('survives a cycle', () => {
    const pos = layeredLayout(
      ['a', 'b'],
      [
        { source: 'a', target: 'b' },
        { source: 'b', target: 'a' },
      ]
    )
    expect(Object.keys(pos)).toHaveLength(2)
  })
})
