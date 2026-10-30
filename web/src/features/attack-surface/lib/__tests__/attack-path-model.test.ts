import { describe, expect, it } from 'vitest'
import { mockupDetail, node } from './attack-path-fixture'
import { transformPathDetail } from '../../hooks/use-attack-path-detail'
import {
  INTERNET,
  assetFindingsHref,
  chokeRows,
  focusSets,
  layoutPaths,
  pathScore,
  shownPaths,
  stepText,
} from '../attack-path-model'

describe('attack-path model', () => {
  it('shows the first path in shortest mode and every path in all mode', () => {
    const d = mockupDetail()
    expect(shownPaths(d, 'shortest')).toEqual([0])
    expect(shownPaths(d, 'all')).toEqual([0, 1])
    expect(shownPaths({ ...d, paths: [] }, 'all')).toEqual([])
  })

  it('lays out internet, entry, hops and the target left to right, the main route straight', () => {
    const l = layoutPaths(mockupDetail(), [0, 1])
    const at = (k: string) => l.nodes.find((n) => n.key === k)!
    expect(at(INTERNET).column).toBe(0)
    expect(at('n1').column).toBe(1)
    expect(at('n2').column).toBe(2)
    expect(at('n3').column).toBe(2)
    expect(at('n0').column).toBe(3)
    // Entry and target sit on the middle row; the two hops above and below.
    expect(at('n1').y).toBe(0)
    expect(at('n0').y).toBe(0)
    expect(at('n2').y).toBeLessThan(0)
    expect(at('n3').y).toBeGreaterThan(0)
    expect(l.edges.map((e) => e.id)).toContain(`${INTERNET}->n1`)
  })

  it('keeps only the edges of shown routes', () => {
    const l = layoutPaths(mockupDetail(), [0])
    expect(l.nodes.map((n) => n.key).sort()).toEqual(['internet', 'n0', 'n1', 'n2'])
    expect(l.edges).toHaveLength(3)
    expect(l.edges.every((e) => e.paths.every((p) => p === 0))).toBe(true)
  })

  it('lights every route through a hovered node, and only the selected route for a path', () => {
    const d = mockupDetail()
    const l = layoutPaths(d, [0, 1])
    const hop = focusSets(l, d, { kind: 'node', key: 'n3' })!
    expect([...hop.nodes].sort()).toEqual(['internet', 'n0', 'n1', 'n3'])
    expect(hop.edges.has('n1->n2')).toBe(false)
    expect(hop.edges.has('n3->n0')).toBe(true)
    const entry = focusSets(l, d, { kind: 'node', key: 'n1' })!
    expect(entry.nodes.size).toBe(5)
    const path = focusSets(l, d, { kind: 'path', index: 0 })!
    expect(path.nodes.has('n3')).toBe(false)
    expect(focusSets(l, d, null)).toBeNull()
  })

  it('lists choke points with the routes they cut out of the routes shown', () => {
    const rows = chokeRows(mockupDetail())
    expect(rows.map((r) => [r.node.name, r.breaks, r.of])).toEqual([
      ['vpn-gw-hq', 2, 2],
      ['jump-host-02', 1, 2],
      ['ci-runner-3', 1, 2],
    ])
  })

  it('never lists a hidden step as a choke point', () => {
    const d = mockupDetail()
    d.nodes[2] = {
      ...node('n2', 'hop'),
      hidden: true,
      name: '',
      assetId: '',
      weight: null,
      finding: null,
    }
    expect(chokeRows(d).map((r) => r.key)).not.toContain('n2')
  })

  it('breaks a path score into its step weights', () => {
    const s = pathScore(mockupDetail(), 0)!
    expect(s.rows.map((r) => r.weight)).toEqual([0.9, 0.6, 0.4])
    expect(s.likelihood).toBe(0.216)
    expect(pathScore(mockupDetail(), 9)).toBeNull()
  })

  it('names a step by CVE, else by title, and opens the asset findings including informational ones', () => {
    const d = mockupDetail()
    expect(stepText(d.nodes[1])).toBe('CVE-2026-30112')
    expect(stepText(d.nodes[2])).toBe('n2 finding')
    expect(stepText({ ...d.nodes[2], finding: null })).toBe('')
    expect(assetFindingsHref('a b')).toBe('/findings?asset_id=a%20b&informational=true')
  })

  it('maps the API response, keeping hidden steps empty', () => {
    const d = transformPathDetail({
      target: 'n0',
      nodes: [
        {
          key: 'n0',
          role: 'target',
          asset_id: 'a',
          name: 'db',
          open_findings: 2,
          kev_findings: 1,
          weight: 0.4,
          basis: 'epss',
        },
        { key: 'n1', role: 'hop', hidden: true, open_findings: 0, kev_findings: 0 },
      ],
      edges: null,
      paths: [{ nodes: ['n1', 'n0'], length: 1, kev_steps: 0 }],
      choke_points: null,
      total_paths: 1,
      capped: false,
      computed_at: '2026-10-25T10:30:00Z',
    })
    expect(d.nodes[1]).toMatchObject({
      hidden: true,
      name: '',
      weight: null,
      basis: null,
      finding: null,
    })
    expect(d.paths[0].likelihood).toBeNull()
    expect(d.edges).toEqual([])
    expect(d.chokePoints).toEqual([])
  })
})
