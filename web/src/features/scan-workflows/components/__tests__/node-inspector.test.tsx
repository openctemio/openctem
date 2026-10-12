import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { NodeInspector } from '../node-inspector'
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability } from '../../lib/capability-graph'

// Radix scroll areas and radios measure themselves; jsdom has none.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const ports: Capability = {
  key: 'scan.ports',
  id: 'scan.ports@1',
  name: 'Port scan',
  tier: 'T1',
  available: true,
  crossCutting: false,
  inPorts: ['hostname'],
  outPorts: ['service'],
  tools: ['naabu', 'masscan'],
  defaultTool: 'naabu',
  params: [
    {
      name: 'rate',
      type: 'integer',
      description: 'Requests per second.',
      enum: [],
      min: 1,
      max: 100000,
    },
    { name: 'top_n', type: 'integer', description: 'Top ports.', enum: [], min: 1, max: 65535 },
  ],
  toolParams: { naabu: { rate: 'rate', top_n: 'top_ports' }, masscan: { rate: 'rate' } },
}

const step: ScanWorkflowStep = {
  id: 's1',
  step_key: 'ports',
  name: 'Ports',
  order: 1,
  ui_position: { x: 0, y: 0 },
  capabilities: ['scan.ports'],
  config: { top_n: 100 },
  max_retries: 0,
  retry_delay_seconds: 0,
}

describe('NodeInspector', () => {
  it('renders only the contract params: an unknown key cannot be entered', () => {
    render(<NodeInspector step={step} capability={ports} onChange={vi.fn()} onClose={vi.fn()} />)
    expect(screen.getByLabelText('rate')).toBeInTheDocument()
    expect(screen.getByLabelText('top_n')).toBeInTheDocument()
    // Exactly the contract params are text inputs; the one run field is the
    // timeout (step retries are not applied yet, so they are not offered).
    expect(screen.getAllByRole('textbox')).toHaveLength(2)
    expect(screen.getAllByRole('spinbutton')).toHaveLength(1)
    expect(screen.queryByLabelText(/Retries/i)).not.toBeInTheDocument()
    expect(screen.getByText('scan.ports@1')).toBeInTheDocument()
  })

  it('refuses a value outside the contract and does not store it', async () => {
    const onChange = vi.fn()
    render(<NodeInspector step={step} capability={ports} onChange={onChange} onClose={vi.fn()} />)
    const rate = screen.getByLabelText('rate')
    await userEvent.type(rate, '1000000')
    await userEvent.tab()
    expect(screen.getByText('At most 100000.')).toBeInTheDocument()
    expect(onChange).not.toHaveBeenCalled()

    await userEvent.clear(rate)
    await userEvent.type(rate, '500')
    await userEvent.tab()
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ config: { top_n: 100, rate: 500 } })
    )
  })

  it('warns which tools cannot run the step with its settings', () => {
    render(<NodeInspector step={step} capability={ports} onChange={vi.fn()} onClose={vi.fn()} />)
    expect(screen.getByText(/masscan does not take top_n/)).toBeInTheDocument()
  })

  it('pins a tool from the selection radio', async () => {
    const onChange = vi.fn()
    render(<NodeInspector step={step} capability={ports} onChange={onChange} onClose={vi.fn()} />)
    await userEvent.click(screen.getByLabelText('One tool'))
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ tool: 'naabu', prefer_tools: [] })
    )
  })

  it('a step without a contract has no params form', () => {
    render(
      <NodeInspector
        step={{ ...step, tool: 'my-scanner', capabilities: ['scan'] }}
        capability={null}
        onChange={vi.fn()}
        onClose={vi.fn()}
      />
    )
    expect(screen.getByText(/has no capability contract/)).toBeInTheDocument()
    expect(screen.queryByLabelText('rate')).toBeNull()
  })

  it('shows the API issues of the step with their fixes', () => {
    render(
      <NodeInspector
        step={step}
        capability={ports}
        issues={[
          {
            code: 'TOOL_UNAVAILABLE',
            node: 'ports',
            message: 'step "Ports": naabu is not on any online sensor',
            fix: 'Pick "Any tool", or install naabu on a sensor.',
          },
        ]}
        onChange={vi.fn()}
        onClose={vi.fn()}
      />
    )
    const list = screen.getByRole('list', { name: 'Problems of this step' })
    expect(list).toHaveTextContent('naabu is not on any online sensor')
    expect(list).toHaveTextContent('Pick "Any tool"')
  })

  it('lists settings outside the contract and removes one', async () => {
    const onChange = vi.fn()
    render(
      <NodeInspector
        step={{ ...step, config: { top_n: 100, top_ports: '1000', exclude: ['/x'] } }}
        capability={ports}
        onChange={onChange}
        onClose={vi.fn()}
      />
    )
    // A template's tool-native key is shown; the executor key is not.
    expect(screen.getByText(/top_ports = "1000"/)).toBeInTheDocument()
    expect(screen.queryByText(/exclude =/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Remove top_ports' }))
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ config: { top_n: 100, exclude: ['/x'] } })
    )
  })
})
