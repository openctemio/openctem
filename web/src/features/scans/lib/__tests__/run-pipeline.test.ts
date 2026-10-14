import { describe, expect, it } from 'vitest'
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import {
  PIPELINE_CARD_WIDTH,
  PIPELINE_GAP_X,
  PIPELINE_SIBLING_GAP,
  blockingUpstream,
  edgeHandOff,
  hasParallelBranches,
  pipelineDirection,
  pipelineLayers,
  pipelineTone,
  skippedReasonText,
  stepDurationLabel,
  stepProgress,
} from '../run-pipeline'

function node(key: string, deps: string[] = [], over: Partial<RunMapNode> = {}): RunMapNode {
  return {
    step_key: key,
    depends_on: deps,
    state: 'pending',
    findings: 0,
    chunks: { total: 0, queued: 0, running: 0, completed: 0, failed: 0 },
    outputs: { total: 0, by_type: {} },
    ...over,
  } as RunMapNode
}

/** Every step is in exactly one layer, after all its dependencies. */
function expectWellLayered(nodes: RunMapNode[], layers: string[][]) {
  const at = new Map<string, number>()
  layers.forEach((l, i) => l.forEach((k) => at.set(k, i)))
  expect(layers.flat().sort()).toEqual(nodes.map((n) => n.step_key).sort())
  for (const n of nodes) {
    for (const d of n.depends_on ?? []) {
      if (at.has(d)) expect(at.get(d)!).toBeLessThan(at.get(n.step_key!)!)
    }
  }
}

describe('pipeline layout', () => {
  it('draws a linear chain as one step per layer, and as a list', () => {
    const nodes = [
      node('subs'),
      node('dns', ['subs']),
      node('ports', ['dns']),
      node('http', ['ports']),
    ]
    const layers = pipelineLayers(nodes)
    expect(layers).toEqual([['subs'], ['dns'], ['ports'], ['http']])
    expectWellLayered(nodes, layers)
    expect(hasParallelBranches(layers)).toBe(false)
    // A chain is a list at any width: no graph canvas around one column.
    expect(pipelineDirection(layers, 4000)).toBeNull()
  })

  it('puts a fan-out side by side and picks the direction that fits', () => {
    const nodes = [
      node('subs'),
      node('dns', ['subs']),
      node('ports', ['dns']),
      node('http', ['dns']),
      node('tls', ['dns']),
    ]
    const layers = pipelineLayers(nodes)
    expect(layers).toEqual([['subs'], ['dns'], ['ports', 'http', 'tls']])
    expectWellLayered(nodes, layers)
    expect(hasParallelBranches(layers)).toBe(true)
    const across = (n: number) => n * PIPELINE_CARD_WIDTH + (n - 1) * PIPELINE_GAP_X
    const side = (n: number) => n * PIPELINE_CARD_WIDTH + (n - 1) * PIPELINE_SIBLING_GAP
    expect(pipelineDirection(layers, across(3))).toBe('LR') // three layers fit across
    expect(pipelineDirection(layers, across(3) - 1)).toBe('TB') // the widest layer fits
    expect(pipelineDirection(layers, side(3) - 1)).toBeNull() // nothing fits: the list
    expect(pipelineDirection(layers, 0)).toBeNull() // not measured yet: the list
  })

  it('lays a diamond out without crossing, the join after both branches', () => {
    const nodes = [node('a'), node('c', ['a']), node('b', ['a']), node('d', ['b', 'c'])]
    const layers = pipelineLayers(nodes)
    expectWellLayered(nodes, layers)
    expect(layers.map((l) => l.length)).toEqual([1, 2, 1])
    expect(layers[2]).toEqual(['d'])
  })

  it('orders a layer by where its dependencies are, so edges do not cross', () => {
    // x1 feeds y2 and x2 feeds y1: the second layer follows the first.
    const nodes = [node('x1'), node('x2'), node('y1', ['x2']), node('y2', ['x1'])]
    expect(pipelineLayers(nodes)).toEqual([
      ['x1', 'x2'],
      ['y2', 'y1'],
    ])
  })

  it('draws every step once, whatever the dependencies say', () => {
    const nodes = [node('a', ['b']), node('b', ['a']), node('c', ['missing', 'c'])]
    const layers = pipelineLayers(nodes)
    expect(layers.flat().sort()).toEqual(['a', 'b', 'c'])
  })
})

describe('step reasons and numbers', () => {
  const byKey = (nodes: RunMapNode[]) => new Map(nodes.map((n) => [n.step_key!, n]))

  it('says which upstream step a skipped step waited on', () => {
    // The live run: the HTTP probe failed, so the templates were skipped.
    const probe = node('probe', [], { name: 'HTTP probe', state: 'failed' })
    const vulns = node('vulns', ['probe'], { name: 'Vulnerability templates', state: 'skipped' })
    const report = node('report', ['vulns'], { state: 'skipped' })
    const m = byKey([probe, vulns, report])
    expect(skippedReasonText(vulns, m)).toBe('Skipped: HTTP probe failed')
    // Further down, the failure is still the reason.
    expect(blockingUpstream(report, m)?.node.step_key).toBe('probe')
    expect(skippedReasonText(probe, m)).toBeNull()
    const lone = node('lone', [], { state: 'skipped' })
    expect(skippedReasonText(lone, byKey([lone]))).toBeNull()
    const canceled = node('up', [], { name: 'Ports', state: 'canceled' })
    const after = node('after', ['up'], { state: 'skipped' })
    expect(skippedReasonText(after, byKey([canceled, after]))).toBe('Skipped: Ports did not run')
  })

  it('times a step and shows its chunk progress', () => {
    const done = node('a', [], {
      started_at: '2026-10-14T05:30:00Z',
      completed_at: '2026-10-14T05:33:12Z',
    })
    expect(stepDurationLabel(done)).toBe('3m 12s')
    const running = node('b', [], { started_at: '2026-10-14T05:30:00Z' })
    expect(stepDurationLabel(running, Date.parse('2026-10-14T05:30:05Z'))).toBe('5s')
    expect(stepDurationLabel(node('c'))).toBeNull()
    expect(
      stepProgress(
        node('d', [], { chunks: { total: 4, queued: 1, running: 1, completed: 1, failed: 1 } })
      )
    ).toBe(50)
    expect(stepProgress(node('e'))).toBeNull()
  })

  it('labels an edge with what flowed along it', () => {
    const map = {
      edges: [
        { from: 'subs', to: 'dns', count: 66 },
        { from: 'dns', to: 'ports', count: 0 },
      ],
    } as RunMap
    expect(edgeHandOff(map, 'subs', 'dns')).toBe('66 outputs')
    expect(edgeHandOff(map, 'dns', 'ports')).toBeNull()
    expect(edgeHandOff(undefined, 'a', 'b')).toBeNull()
  })

  it('draws each state in its family', () => {
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
        'x',
      ].map(pipelineTone)
    ).toEqual([
      'pending',
      'waiting',
      'running',
      'done',
      'partial',
      'failed',
      'skipped',
      'skipped',
      'pending',
    ])
  })
})
