import { beforeAll, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { useNodesState, type Edge } from '@xyflow/react'

import type { WorkflowCatalog } from '@/lib/api/workflow-types'
import type { AutomationNode } from '../../lib/automation-graph'
import { AutomationCanvas } from '../automation-canvas'

vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: () => ({ data: { data: [] }, isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

const catalog: WorkflowCatalog = {
  triggers: [{ type: 'finding_created', allowed: true }],
  actions: [
    { type: 'add_tags', permission: 'findings:write', allowed: true },
    { type: 'trigger_scan', permission: 'scans:execute', allowed: false },
  ],
  notifications: [{ type: 'email', permission: 'integrations:read', allowed: true }],
}

const graph: AutomationNode[] = [
  {
    id: 't1',
    type: 'trigger',
    position: { x: 0, y: 0 },
    data: { label: 'On new finding', nodeKey: 't1', config: { trigger_type: 'finding_created' } },
  },
  {
    id: 'a1',
    type: 'action',
    position: { x: 0, y: 100 },
    data: { label: 'Call out', nodeKey: 'a1', config: { action_type: 'http_request' } },
  },
]
const edges: Edge[] = [{ id: 'e1', source: 't1', target: 'a1' }]

function renderCanvas(props: Partial<React.ComponentProps<typeof AutomationCanvas>> = {}) {
  const setNodes = vi.fn()
  render(
    <AutomationCanvas
      nodes={graph}
      edges={edges}
      setNodes={setNodes}
      setEdges={vi.fn()}
      onNodesChange={vi.fn()}
      onEdgesChange={vi.fn()}
      catalog={catalog}
      {...props}
    />
  )
  return { setNodes }
}

describe('AutomationCanvas palette', () => {
  it('lists exactly the catalog entries plus the condition step, nothing else', () => {
    renderCanvas()
    const palette = screen.getByTestId('automation-palette')
    const ids = within(palette)
      .getAllByRole('button')
      .map((b) => b.getAttribute('data-testid'))
    expect(ids).toEqual([
      'palette-trigger-finding_created',
      'palette-condition-condition',
      'palette-action-add_tags',
      'palette-action-trigger_scan',
      'palette-notification-email',
    ])
  })

  it('shows an entry the caller may not add as disabled, with the missing permission', () => {
    renderCanvas()
    const scan = screen.getByTestId('palette-action-trigger_scan')
    expect(scan).toBeDisabled()
    expect(scan).toHaveTextContent('Needs scans:execute')
    expect(screen.getByTestId('palette-action-add_tags')).toBeEnabled()
  })

  it('adds a step preset to the clicked catalog type', () => {
    const { setNodes } = renderCanvas()
    fireEvent.click(screen.getByTestId('palette-action-add_tags'))
    const next = setNodes.mock.calls[0][0](graph) as AutomationNode[]
    expect(next.at(-1)?.data.config.action_type).toBe('add_tags')
    expect(next.at(-1)?.data.label).toBe('Add Tags')
  })

  it('has no palette when the viewer may not edit', () => {
    renderCanvas({ readOnly: true })
    expect(screen.queryByTestId('automation-palette')).toBeNull()
  })
})

describe('AutomationCanvas steps', () => {
  it('renders a stored step of a removed type as "Removed type: <id>"', () => {
    renderCanvas()
    const removed = screen.getAllByTestId('removed-type')
    expect(removed[0]).toHaveTextContent('Removed type: http_request')
  })

  it('shows preview counts on the steps', () => {
    renderCanvas({
      counts: new Map([['a1', { in: 12, out: 10, skipped: { no_change: 2 } }]]),
    })
    const counts = screen.getAllByTestId('step-counts')[0]
    expect(counts).toHaveTextContent('in 12')
    expect(counts).toHaveTextContent('out 10')
    expect(counts).toHaveTextContent('2 nothing to change')
  })

  it('selects the step a validate problem points at', async () => {
    function Harness() {
      const [nodes, setNodes, onNodesChange] = useNodesState<AutomationNode>(graph)
      return (
        <AutomationCanvas
          nodes={nodes}
          edges={edges}
          setNodes={setNodes}
          setEdges={vi.fn()}
          onNodesChange={onNodesChange}
          onEdgesChange={vi.fn()}
          catalog={catalog}
          focusRequest={{ nodeKey: 'a1', seq: 1 }}
        />
      )
    }
    render(<Harness />)
    expect(await screen.findByLabelText('Name')).toHaveValue('Call out')
  })
})
