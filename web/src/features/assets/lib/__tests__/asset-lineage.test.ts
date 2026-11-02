import { describe, it, expect } from 'vitest'
import {
  discoverySourceLabel,
  isLineageRoot,
  lineageEdgeLabel,
  lineageSelf,
  lineageSteps,
  type AssetLineage,
} from '../asset-lineage'
import { defaultT } from '../default-t'

const chain: AssetLineage = {
  max_depth: 5,
  truncated: false,
  nodes: [
    { depth: 0, hidden: false, id: 'a', name: 'app.dev.example.com', type: 'subdomain' },
    { depth: 1, hidden: true, via: 'parent' },
    { depth: 2, hidden: false, via: 'contains', id: 'r', name: 'example.com', type: 'domain' },
  ],
}

describe('lineageSteps', () => {
  it('lists the root first and carries the edge from the step above', () => {
    const steps = lineageSteps(chain)
    expect(steps.map((s) => s.node.depth)).toEqual([2, 1, 0])
    expect(steps.map((s) => s.edge)).toEqual([undefined, 'contains', 'parent'])
    expect(steps.map((s) => s.isSelf)).toEqual([false, false, true])
  })

  it('is empty without data', () => {
    expect(lineageSteps(undefined)).toEqual([])
    expect(lineageSteps({ nodes: [], max_depth: 5, truncated: false })).toEqual([])
  })
})

describe('lineageSelf and isLineageRoot', () => {
  it('finds the asset and tells a root', () => {
    expect(lineageSelf(chain)?.id).toBe('a')
    expect(isLineageRoot(chain)).toBe(false)
    const root = { nodes: [chain.nodes[0]], max_depth: 5, truncated: false }
    expect(isLineageRoot(root)).toBe(true)
    // A chain cut at the cap is not a root, even with one node shown.
    expect(isLineageRoot({ ...root, truncated: true })).toBe(false)
  })
})

describe('labels', () => {
  it('names known sources and humanises unknown ones', () => {
    expect(discoverySourceLabel(defaultT, 'cert_transparency')).toBe('Certificate logs')
    expect(discoverySourceLabel(defaultT, 'some_new-source')).toBe('Some new source')
  })

  it('reads each edge downwards', () => {
    expect(lineageEdgeLabel(defaultT, 'parent')).toBe('Parent of')
    expect(lineageEdgeLabel(defaultT, 'contains')).toBe('Contains')
    expect(lineageEdgeLabel(defaultT, 'exposes')).toBe('Exposes')
  })
})
