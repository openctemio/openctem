import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import type { WorkflowRun } from '@/lib/api/workflow-types'
import { AutomationRunDetail } from '../automation-run-sheet'
import { DeliveriesList, ValidationPanel } from '../automation-trace-panels'

const perms = vi.hoisted(() => ({ publish: true, write: true }))
const api = vi.hoisted(() => ({
  resumeWorkflowRun: vi.fn(),
  cancelWorkflowRun: vi.fn(),
  invalidateWorkflowRunsCache: vi.fn(),
}))

vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) =>
    p === 'automations:publish' ? perms.publish : p === 'automations:write' ? perms.write : false,
}))
vi.mock('@/lib/api/workflow-hooks', () => ({ ...api, useWorkflowRun: vi.fn() }))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

beforeEach(() => {
  vi.clearAllMocks()
  perms.publish = true
  perms.write = true
})

describe('ValidationPanel', () => {
  it('selects the step a problem points at and translates known codes', () => {
    const onSelect = vi.fn()
    render(
      <ValidationPanel
        result={{
          problems: [
            { code: 'STATUS_NOT_ALLOWED', node_key: 'a1', message: 'status resolved refused' },
          ],
          warnings: [{ code: 'SOMETHING_NEW', message: 'A message from the API' }],
        }}
        nodeName={(k) => (k === 'a1' ? 'Close it' : undefined)}
        onSelect={onSelect}
      />
    )
    const problem = screen.getByTestId('issue-STATUS_NOT_ALLOWED')
    expect(problem).toHaveTextContent('Close it')
    expect(problem).toHaveTextContent(
      'An automation may only set a finding to Confirmed or In progress.'
    )
    fireEvent.click(problem)
    expect(onSelect).toHaveBeenCalledWith('a1')
    // An unknown code falls back to the API's message; without a node it is not a button.
    const warning = screen.getByTestId('issue-SOMETHING_NEW')
    expect(warning).toHaveTextContent('A message from the API')
    expect(warning.tagName).toBe('DIV')
  })
})

function run(over: Partial<WorkflowRun> = {}): WorkflowRun {
  return {
    id: 'r58',
    workflow_id: 'w1',
    tenant_id: 't1',
    trigger_type: 'finding_created',
    status: 'completed',
    total_nodes: 2,
    completed_nodes: 2,
    failed_nodes: 0,
    created_at: '2026-10-22T00:00:00Z',
    mode: 'simulate',
    retained_until: '2026-11-21T00:00:00Z',
    node_runs: [
      {
        id: 'nr1',
        workflow_run_id: 'r58',
        node_id: 'n1',
        node_key: 'c1',
        node_type: 'condition',
        status: 'completed',
        in_count: 61,
        out_count: 14,
        skipped: { condition_false: 47 },
      },
    ],
    deliveries: [
      {
        id: 'd1',
        node_key: 'n1',
        channel: 'slack',
        target: '#sec-oncall',
        mode: 'simulate',
        status: 'simulated',
        attempts: 0,
        payload: { title: 'KEV on web-01' },
        created_at: '2026-10-22T00:00:00Z',
      },
    ],
    ...over,
  }
}

describe('AutomationRunDetail', () => {
  it('shows per-step counts with skipped reasons', () => {
    render(
      <AutomationRunDetail
        run={run()}
        nodeName={(k) => (k === 'c1' ? 'Internet-facing' : undefined)}
      />
    )
    const trace = screen.getByTestId('step-trace')
    expect(trace).toHaveTextContent('Internet-facing')
    expect(trace).toHaveTextContent('61')
    expect(trace).toHaveTextContent('47 condition false')
  })

  it('lists simulate deliveries as never sent', () => {
    render(<AutomationRunDetail run={run()} nodeName={() => undefined} />)
    expect(screen.getByRole('tab', { name: 'Would send 1' })).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Would send 1' }))
    const list = screen.getByTestId('deliveries-list')
    expect(list).toHaveTextContent('Slack')
    expect(list).toHaveTextContent('#sec-oncall')
    expect(list).toHaveTextContent('Never sent: simulate')
  })

  it('labels live deliveries as sent', () => {
    render(
      <AutomationRunDetail
        run={run({
          mode: 'live',
          deliveries: [
            {
              id: 'd2',
              node_key: 'n2',
              channel: 'jira',
              target: 'SEC',
              mode: 'live',
              status: 'sent',
              attempts: 1,
              external_ref: 'SEC-12',
              created_at: '2026-10-22T00:00:00Z',
            },
          ],
        })}
        nodeName={() => undefined}
      />
    )
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Sent 1' }))
    expect(screen.getByTestId('deliveries-list')).toHaveTextContent('SEC-12')
  })

  it('continues or cancels a run paused at the change cap', async () => {
    api.resumeWorkflowRun.mockResolvedValue(run())
    api.cancelWorkflowRun.mockResolvedValue(undefined)
    render(
      <AutomationRunDetail
        run={run({ status: 'paused', pause_reason: 'blast_radius', mode: 'live' })}
        nodeName={() => undefined}
      />
    )
    expect(screen.getByTestId('run-paused')).toHaveTextContent('Paused at the change cap')
    fireEvent.click(screen.getByRole('button', { name: /Continue/ }))
    await waitFor(() => expect(api.resumeWorkflowRun).toHaveBeenCalledWith('r58'))
    fireEvent.click(screen.getByRole('button', { name: /Cancel run/ }))
    await waitFor(() => expect(api.cancelWorkflowRun).toHaveBeenCalledWith('r58'))
  })

  it('needs the publish permission to continue a paused run', () => {
    perms.publish = false
    render(
      <AutomationRunDetail
        run={run({ status: 'paused', pause_reason: 'blast_radius' })}
        nodeName={() => undefined}
      />
    )
    expect(screen.getByRole('button', { name: /Continue/ })).toBeDisabled()
    // Cancelling narrows: the write permission is enough.
    expect(screen.getByRole('button', { name: /Cancel run/ })).toBeEnabled()
  })

  it('needs the write permission to cancel a paused run', () => {
    perms.write = false
    render(
      <AutomationRunDetail
        run={run({ status: 'paused', pause_reason: 'blast_radius' })}
        nodeName={() => undefined}
      />
    )
    expect(screen.getByRole('button', { name: /Cancel run/ })).toBeDisabled()
  })
})

describe('DeliveriesList', () => {
  it('shows a preview would-send (no mode or status) as never sent', () => {
    render(
      <DeliveriesList
        mode="simulate"
        deliveries={[{ node_key: 'n1', channel: 'teams', target: 'SecOps', payload: {} }]}
      />
    )
    expect(screen.getByTestId('deliveries-list')).toHaveTextContent('Never sent: simulate')
  })
})
