import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { DependencyGraph, GraphNode } from '../../api/types'

const push = vi.fn()
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }))

import { DependencyGraphView, layoutGraph, vulnerablePaths } from '../dependency-graph'

function node(
  id: string,
  name: string,
  vulns: Partial<GraphNode['vulnerabilities']> = {}
): GraphNode {
  return {
    id,
    component_id: `c-${id}`,
    version_id: `v-${id}`,
    name,
    version: '1.0.0',
    purl: `pkg:npm/${name}@1.0.0`,
    ecosystem: 'npm',
    relationship: 'transitive',
    vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, ...vulns },
    kev: false,
  }
}

// app -> lib -> vuln ; app -> safe ; other -> safe
const graph: DependencyGraph = {
  nodes: [
    node('app', 'app'),
    node('lib', 'lib'),
    node('vuln', 'vuln', { high: 2 }),
    node('safe', 'safe'),
    node('other', 'other'),
  ],
  edges: [
    { from: 'app', to: 'lib' },
    { from: 'lib', to: 'vuln' },
    { from: 'app', to: 'safe' },
    { from: 'other', to: 'safe' },
  ],
  truncated: false,
}

describe('dependency graph', () => {
  it('lays nodes out in layers from the roots', () => {
    const { nodes, layers } = layoutGraph(graph)
    const layer = Object.fromEntries(nodes.map((n) => [n.id, n.layer]))
    expect(layer).toMatchObject({ app: 0, other: 0, lib: 1, safe: 1, vuln: 2 })
    expect(layers).toBe(3)
  })

  it('highlights vulnerable packages and every path to them', () => {
    expect([...vulnerablePaths(graph)].sort()).toEqual(['app', 'lib', 'vuln'])
  })

  it('offers a list view whose rows link to the package', async () => {
    render(<DependencyGraphView graph={graph} />)
    await userEvent.click(screen.getByRole('radio', { name: /list/i }))
    const link = screen.getByRole('link', { name: /vuln/ })
    expect(link.getAttribute('href')).toBe('/components/c-vuln')
  })

  it('opens a package from the graph with the keyboard', async () => {
    render(<DependencyGraphView graph={graph} />)
    const target = screen.getAllByRole('link', { name: 'lib 1.0.0' })[0]
    target.focus()
    await userEvent.keyboard('{Enter}')
    expect(push).toHaveBeenCalledWith('/components/c-lib')
  })
})
