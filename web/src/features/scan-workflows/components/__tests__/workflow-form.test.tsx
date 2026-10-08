/**
 * research/62 P0-9 (SG-7/SG-8): the workflow form shows only settings that
 * work, and editing a workflow never rewrites its steps.
 * - no Triggers tab, no "Notify on failure": both were stored and never used
 * - editing sends no `steps`: the form showed a few fields of each step and
 *   saving replaced the rest (prefer_tools, conditions, config...)
 * - creating still sends the steps entered
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScanWorkflowForm } from '../workflow-form'
import type { ScanWorkflow } from '@/lib/api'

vi.mock('@/lib/api/tool-hooks', () => ({
  useToolsWithConfig: () => ({ data: { items: [] }, isLoading: false }),
  useToolAvailability: () => ({ data: undefined }),
}))
vi.mock('@/lib/api/platform-hooks', () => ({
  usePlatformScanning: () => ({ offered: false }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const workflow = {
  id: 'w1',
  tenant_id: 't1',
  name: 'Recon',
  description: '',
  version: 1,
  is_active: true,
  is_system_template: false,
  tags: [],
  settings: {
    max_parallel_steps: 3,
    fail_fast: true,
    timeout_seconds: 1800,
    sensor_preference: 'auto',
  },
  steps: [
    {
      id: 's1',
      step_key: 'ports',
      name: 'Ports',
      order: 1,
      ui_position: { x: 0, y: 0 },
      capabilities: ['scan.ports'],
      prefer_tools: ['naabu'],
      max_retries: 0,
      retry_delay_seconds: 0,
    },
  ],
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
} as unknown as ScanWorkflow

describe('ScanWorkflowForm', () => {
  it('shows no Triggers tab and no failure notification switch', () => {
    render(<ScanWorkflowForm onSubmit={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.queryByRole('tab', { name: /Triggers/i })).not.toBeInTheDocument()
    expect(screen.queryByText(/Notify on Failure/i)).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Steps/i })).toBeInTheDocument()
  })

  it('edits a workflow without its steps, keeping its other settings', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined)
    render(<ScanWorkflowForm workflow={workflow} onSubmit={onSubmit} onCancel={vi.fn()} />)
    expect(screen.queryByRole('tab', { name: /Steps/i })).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await userEvent.click(screen.getByRole('button', { name: /Update Workflow/i }))

    expect(onSubmit).toHaveBeenCalledTimes(1)
    const sent = onSubmit.mock.calls[0][0]
    expect(sent).not.toHaveProperty('steps')
    expect(sent).not.toHaveProperty('triggers')
    expect(sent.settings).toMatchObject({ fail_fast: true, timeout_seconds: 1800 })
    expect(sent.settings).not.toHaveProperty('notify_on_failure')
  })

  it('creates a workflow with the steps entered', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined)
    render(<ScanWorkflowForm onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.type(screen.getByLabelText(/Workflow Name/i), 'New one')
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    await userEvent.click(screen.getByRole('button', { name: /Create Workflow/i }))

    expect(onSubmit).toHaveBeenCalledTimes(1)
    const sent = onSubmit.mock.calls[0][0]
    expect(sent.name).toBe('New one')
    expect(sent.steps).toHaveLength(1)
    expect(sent).not.toHaveProperty('triggers')
  })
})
