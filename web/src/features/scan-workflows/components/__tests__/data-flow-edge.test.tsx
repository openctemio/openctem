import { render, screen } from '@testing-library/react'
import { beforeAll, describe, expect, it } from 'vitest'
import { Position, ReactFlow, ReactFlowProvider, type Edge, type Node } from '@xyflow/react'
import { DataFlowEdge } from '../data-flow-edge'
import type { EdgeDescription } from '../../lib/capability-graph'

// React Flow observes node sizes; jsdom has no ResizeObserver.
beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

// Sizes and handles given up front (as for server rendering): jsdom
// cannot measure them.
const size = { width: 120, height: 40 }
const handles = [
  { type: 'source' as const, position: Position.Right, x: 120, y: 20, width: 1, height: 1 },
  { type: 'target' as const, position: Position.Left, x: 0, y: 20, width: 1, height: 1 },
]
const nodes: Node[] = [
  { id: 'a', position: { x: 0, y: 0 }, data: { label: 'HTTP probe' }, ...size, handles },
  {
    id: 'b',
    position: { x: 400, y: 0 },
    data: { label: 'Vulnerability templates' },
    ...size,
    handles,
  },
]

function draw(description: EdgeDescription, zoom = 1) {
  const edges: Edge[] = [
    {
      id: 'a-b',
      source: 'a',
      target: 'b',
      type: 'dataFlow',
      data: { description },
      ariaLabel: description.text,
    },
  ]
  return render(
    <div style={{ width: 800, height: 400 }}>
      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          edgeTypes={{ dataFlow: DataFlowEdge }}
          defaultViewport={{ x: 0, y: 0, zoom }}
          minZoom={0.1}
        />
      </ReactFlowProvider>
    </div>
  )
}

const data: EdgeDescription = {
  flow: { state: 'data', types: ['url', 'ip'] },
  label: 'url · ip',
  text: 'HTTP probe passes URL, IP address to Vulnerability templates',
}

describe('DataFlowEdge', () => {
  it('labels the line with the types and names the edge with the sentence', async () => {
    draw(data)
    const label = await screen.findByText('url · ip')
    expect(label).toHaveAttribute('data-edge-state', 'data')
    expect(label).toHaveAttribute('title', data.text)
    expect(screen.getByRole('group', { name: data.text })).toBeInTheDocument()
  })

  it('marks a connection that passes nothing', async () => {
    draw({
      flow: { state: 'invalid', types: [], reason: 'no_match' },
      label: 'no matching type',
      text: 'Web crawl takes none of the types Subdomain discovery gives',
    })
    expect(await screen.findByText('no matching type')).toHaveAttribute(
      'data-edge-state',
      'invalid'
    )
  })

  it('leaves the label out when zoomed far out; the edge keeps its name', async () => {
    draw(data, 0.3)
    expect(await screen.findByRole('group', { name: data.text })).toBeInTheDocument()
    expect(screen.queryByText('url · ip')).toBeNull()
  })
})
