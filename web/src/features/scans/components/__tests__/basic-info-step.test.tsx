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
                  { id: 'a1', name: 'Subdomain discovery', tool: '' },
                  { id: 'a2', name: 'DNS resolution', tool: '' },
                ],
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
})
