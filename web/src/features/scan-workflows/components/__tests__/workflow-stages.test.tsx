import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { WorkflowStages } from '../workflow-stages'
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability, CapabilityTable } from '../../lib/capability-graph'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const cap = (key: string, name: string, tools: string[]): Capability => ({
  key,
  id: `${key}@1`,
  name,
  tier: 'T1',
  available: true,
  crossCutting: false,
  inPorts: [],
  outPorts: [],
  tools,
  defaultTool: tools[0],
  params: [],
  toolParams: {},
})

const table: CapabilityTable = {
  capabilities: [
    cap('discover.subdomains', 'Subdomain discovery', ['subfinder']),
    cap('probe.http', 'HTTP probe', ['httpx']),
    cap('scan.ports', 'Port scan', ['naabu']),
    cap('vuln.templates', 'Vulnerability templates', ['nuclei']),
  ],
  adapters: [],
  portLabels: {},
}

const step = (
  key: string,
  name: string,
  extra: Partial<ScanWorkflowStep> = {}
): ScanWorkflowStep => ({
  id: key,
  step_key: key,
  name,
  order: 1,
  ui_position: { x: 0, y: 0 },
  capabilities: [],
  depends_on: [],
  timeout_seconds: 600,
  max_retries: 0,
  retry_delay_seconds: 0,
  ...extra,
})

// Full Reconnaissance: subdomains -> (http, ports) -> vulns.
const recon = [
  step('subs', 'Subdomain Enumeration', { capabilities: ['discover.subdomains'] }),
  step('http', 'HTTP Probing', { capabilities: ['probe.http'], depends_on: ['subs'] }),
  step('ports', 'Port Scanning', { tool: 'naabu', depends_on: ['subs'] }),
  step('vulns', 'Vulnerability Scanning', {
    capabilities: ['vuln.templates'],
    prefer_tools: ['nuclei'],
    depends_on: ['http', 'ports'],
  }),
]

describe('WorkflowStages', () => {
  it('groups parallel steps in one stage, with a heading per stage', () => {
    render(<WorkflowStages steps={recon} table={table} maxParallel={3} />)
    const stages = screen.getAllByRole('heading', { level: 4 })
    expect(stages.map((h) => h.textContent)).toEqual([
      'Stage 1',
      'Stage 2' + '2 in parallel',
      'Stage 3',
    ])
    const second = screen.getByRole('heading', { name: /Stage 2/ }).closest('li')!
    expect(within(second).getByText('HTTP probe')).toBeInTheDocument()
    expect(within(second).getByText('Port scan')).toBeInTheDocument()
  })

  it('shows capability first, then the tool mode, and what a join waits for', () => {
    render(<WorkflowStages steps={recon} table={table} />)
    expect(screen.getAllByText('Any tool')).toHaveLength(2)
    expect(screen.getByText('Pinned: naabu')).toBeInTheDocument()
    expect(screen.getByText('Preferred: nuclei')).toBeInTheDocument()
    expect(screen.getByText('Waits for: HTTP Probing, Port Scanning')).toBeInTheDocument()
  })

  it('summarizes concurrency, the longest chain and the duration bound', () => {
    render(<WorkflowStages steps={recon} table={table} maxParallel={1} />)
    expect(screen.getByText(/At most 2 at once/)).toBeInTheDocument()
    expect(screen.getByText('Longest chain: 3 steps')).toBeInTheDocument()
    expect(screen.getByText('Up to 30 min by step timeouts')).toBeInTheDocument()
    // The limit is lower than what the graph allows.
    expect(screen.getByRole('status')).toHaveTextContent('Up to 2 steps could run at once')
  })

  it('warns about a tool no sensor offers and unpublished draft changes', () => {
    render(
      <WorkflowStages
        steps={recon}
        table={table}
        draftChanged
        toolAvailable={(t) => t !== 'naabu'}
      />
    )
    expect(screen.getByText('No online sensor offers naabu.')).toBeInTheDocument()
    expect(screen.getByText(/draft has changes that are not published/)).toBeInTheDocument()
  })

  it('a cycle shows the problem instead of crashing', () => {
    render(
      <WorkflowStages
        steps={[step('a', 'A', { depends_on: ['b'] }), step('b', 'B', { depends_on: ['a'] })]}
      />
    )
    expect(screen.getByRole('alert')).toHaveTextContent('wait for each other in a loop: A, B')
  })

  it('toggles to a read-only graph and offers the builder', async () => {
    render(<WorkflowStages steps={recon} table={table} builderHref="/scans/workflows/w1" />)
    expect(screen.getByRole('link', { name: /Open in builder/ })).toHaveAttribute(
      'href',
      '/scans/workflows/w1'
    )
    await userEvent.click(screen.getByRole('button', { name: /Graph/ }))
    expect(screen.getByRole('img', { name: 'Graph of the workflow steps' })).toBeInTheDocument()
  })

  it('colours steps by run status', () => {
    render(
      <WorkflowStages steps={recon} table={table} status={{ subs: 'completed', http: 'failed' }} />
    )
    expect(screen.getByText('Completed')).toBeInTheDocument()
    expect(screen.getByText('Failed')).toBeInTheDocument()
  })

  it('shows a per-step badge and reports the chosen step', async () => {
    const chosen: string[] = []
    render(
      <WorkflowStages
        steps={recon}
        table={table}
        badge={{ ports: <span>chunks 3/5</span> }}
        onSelectStep={(k) => chosen.push(k)}
      />
    )
    expect(screen.getByText('chunks 3/5')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Port scan'))
    expect(chosen).toEqual(['ports'])
  })
})
