import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { BasicInfoStep } from '../new-scan/basic-info-step'
import { DEFAULT_NEW_SCAN } from '../../types'

const workflowCalls: unknown[] = []
vi.mock('@/lib/api/scan-workflow-hooks', () => ({
  useScanWorkflows: (filters: unknown) => {
    workflowCalls.push(filters)
    return {
      data: filters
        ? {
            data: [
              {
                id: 'starter-discover',
                name: 'Discover',
                description: 'Find subdomains, resolve them, probe web services.',
                is_system_template: true,
                tags: ['starter', 'discovery'],
                steps: [
                  { id: 'a1', step_key: 'subs', name: 'Subdomain discovery', tool: '' },
                  {
                    id: 'a2',
                    step_key: 'dns',
                    name: 'DNS resolution',
                    tool: '',
                    depends_on: ['subs'],
                  },
                  {
                    id: 'a3',
                    step_key: 'http',
                    name: 'HTTP probe',
                    tool: '',
                    depends_on: ['subs'],
                  },
                ],
              },
              {
                id: 'starter-code',
                name: 'Code / CI',
                description: 'Scan repositories.',
                is_system_template: true,
                tags: ['starter', 'code'],
                steps: [{ id: 'c1', name: 'Static analysis', tool: '' }],
                readiness: {
                  state: 'ci_only',
                  steps: [
                    {
                      step_key: 'sast',
                      name: 'Static analysis',
                      state: 'ci_only',
                      reason: 'Static analysis runs in your CI pipeline',
                      fix: 'Set up the CI pipeline integration',
                    },
                  ],
                },
              },
              {
                id: 'net-blocked',
                name: 'Network sweep',
                description: 'Ports then HTTP.',
                steps: [],
                readiness: {
                  state: 'blocked',
                  steps: [
                    {
                      step_key: 'ports',
                      name: 'Port scan',
                      state: 'blocked',
                      reason: 'No sensor offers Port scan',
                      fix: 'Add a sensor with naabu',
                    },
                  ],
                },
              },
              {
                id: 'p1',
                name: 'External discovery',
                description: 'subfinder then httpx',
                steps: [
                  { id: 's1', step_key: 'subs', name: 'Subdomains', tool: 'subfinder' },
                  {
                    id: 's2',
                    step_key: 'probe',
                    name: 'Probe',
                    tool: 'httpx',
                    depends_on: ['subs'],
                  },
                ],
              },
            ],
          }
        : undefined,
      isLoading: false,
    }
  },
}))
let workflowsModuleOn = true
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: (id: string) => (id === 'scan_workflows' ? workflowsModuleOn : true),
}))

vi.mock('@/lib/api/tool-hooks', () => ({
  useTools: () => ({
    data: { items: [{ id: 't1', name: 'trivy', display_name: 'Trivy', is_active: true }] },
    isLoading: false,
  }),
  // Availability unknown: nothing is disabled.
  useToolAvailability: () => ({ data: undefined }),
  useToolsWithConfig: () => ({ data: undefined }),
}))
vi.mock('@/features/scan-workflows/lib/use-capability-table', () => ({
  useCapabilityTable: () => ({
    table: { capabilities: [], adapters: [], portLabels: {} },
    isLoading: false,
  }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// Radix Select needs these in jsdom.
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

describe('BasicInfoStep', () => {
  beforeEach(() => {
    workflowCalls.length = 0
    workflowsModuleOn = true
  })

  it('offers no workflow when the scan workflows module is off (the API refuses one)', () => {
    workflowsModuleOn = false
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} />)
    expect(screen.queryByRole('radio', { name: 'Discover' })).toBeNull()
    expect(screen.queryByRole('radio', { name: 'Another workflow' })).toBeNull()
    expect(screen.queryByText('What to run')).toBeNull()
    expect(screen.getByLabelText('Scanner')).toBeInTheDocument()
    expect(workflowCalls.every((f) => f === undefined)).toBe(true)
  })

  it('still shows the workflow of a workflow scan being edited when the module is off', () => {
    workflowsModuleOn = false
    render(
      <BasicInfoStep
        data={{ ...DEFAULT_NEW_SCAN, mode: 'workflow', workflowId: 'starter-discover' }}
        onChange={vi.fn()}
        lockMode
      />
    )
    expect(workflowCalls.some((f) => f !== undefined)).toBe(true)
  })

  it('single mode asks for a scanner from the tool registry (no fake scan types)', () => {
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} />)
    expect(screen.getByLabelText('Scanner')).toBeInTheDocument()
    expect(screen.queryByText('Full Scan')).not.toBeInTheDocument()
    expect(screen.queryByText('Compliance')).not.toBeInTheDocument()
  })

  it('offers a single check and the starter workflows first', () => {
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} />)
    expect(screen.getByRole('radio', { name: 'Single check' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Discover' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Another workflow' })).toBeInTheDocument()
    // A tenant workflow is not a starter.
    expect(screen.queryByRole('radio', { name: 'External discovery' })).toBeNull()
    expect(screen.getByText('Subdomain discovery')).toBeInTheDocument()
    // The card summarizes stages: parallel steps are named together.
    expect(screen.getByText('DNS resolution + HTTP probe (in parallel)')).toBeInTheDocument()
  })

  it('choosing a starter makes a workflow scan of that template', async () => {
    const onChange = vi.fn()
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={onChange} />)
    await userEvent.click(screen.getByRole('radio', { name: 'Discover' }))
    expect(onChange).toHaveBeenLastCalledWith({
      mode: 'workflow',
      scannerName: '',
      workflowId: 'starter-discover',
    })
  })

  it('a chosen starter needs no further workflow pick', () => {
    render(
      <BasicInfoStep
        data={{ ...DEFAULT_NEW_SCAN, mode: 'workflow', workflowId: 'starter-discover' }}
        onChange={vi.fn()}
      />
    )
    expect(screen.getByRole('radio', { name: 'Discover' })).toBeChecked()
    expect(screen.queryByLabelText('Workflow')).toBeNull()
  })

  it('choosing a scanner reports its registry name', async () => {
    const onChange = vi.fn()
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={onChange} />)
    await userEvent.click(screen.getByLabelText('Scanner'))
    await userEvent.click(await screen.findByRole('option', { name: 'Trivy' }))
    expect(onChange).toHaveBeenCalledWith({ scannerName: 'trivy' })
  })

  it('workflow mode lists the real workflows and shows the chosen one’s steps', () => {
    render(
      <BasicInfoStep
        data={{ ...DEFAULT_NEW_SCAN, mode: 'workflow', workflowId: 'p1' }}
        onChange={vi.fn()}
      />
    )
    expect(workflowCalls.at(-1)).toMatchObject({ is_active: true })
    expect(screen.getAllByText('External discovery').length).toBeGreaterThan(0)
    // The chosen workflow's steps, as stages of its dependency graph.
    expect(screen.getByRole('heading', { name: 'Stage 1' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Stage 2' })).toBeInTheDocument()
    expect(screen.getByText('Pinned: subfinder')).toBeInTheDocument()
    expect(screen.getByText('Pinned: httpx')).toBeInTheDocument()
    expect(screen.queryByText('Full Reconnaissance')).not.toBeInTheDocument()
  })

  it('Edit (lockMode) does not offer switching between single and workflow', async () => {
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} lockMode />)
    expect(screen.queryByRole('radio', { name: 'Single check' })).toBeNull()
    await userEvent.click(screen.getByText('Advanced Options'))
    expect(screen.queryByText('Workflow Scan')).not.toBeInTheDocument()
    expect(screen.getByText('Sensor Preference')).toBeInTheDocument()
    // Nothing to offer: the workflows are not fetched.
    expect(workflowCalls.every((f) => f === undefined)).toBe(true)
  })

  it('asks the API for readiness and shows a workflow that cannot run off, with why and the fix', () => {
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} />)
    expect(workflowCalls.at(-1)).toMatchObject({ include: 'readiness' })
    const code = screen.getByRole('radio', { name: 'Code / CI' })
    expect(code).toBeDisabled()
    expect(screen.getByText(/runs in your CI pipeline/i)).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Set up the CI pipeline integration' })
    ).toHaveAttribute('href', '/ci-cd')
    // A runnable starter stays selectable.
    expect(screen.getByRole('radio', { name: 'Discover' })).toBeEnabled()
  })

  it('lists workflows that cannot run last, off, under Not available', async () => {
    render(
      <BasicInfoStep
        data={{ ...DEFAULT_NEW_SCAN, mode: 'workflow', workflowId: undefined }}
        onChange={vi.fn()}
      />
    )
    await userEvent.click(screen.getByRole('combobox', { name: 'Workflow' }))
    expect(await screen.findByText('Not available')).toBeInTheDocument()
    const blocked = screen.getByRole('option', { name: /Network sweep/ })
    expect(blocked).toHaveAttribute('aria-disabled', 'true')
    const options = screen.getAllByRole('option').map((o) => o.textContent ?? '')
    expect(options.findIndex((o) => o.includes('External discovery'))).toBeLessThan(
      options.findIndex((o) => o.includes('Network sweep'))
    )
  })
})
