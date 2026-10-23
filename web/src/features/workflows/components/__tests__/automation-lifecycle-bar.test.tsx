import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ApiClientError } from '@/lib/api/error-handler'
import type { Workflow } from '@/lib/api/workflow-types'
import { AutomationLifecycleBar, GoLiveChecks } from '../automation-lifecycle-bar'

const perms = vi.hoisted(() => ({ write: true, publish: true }))
const me = vi.hoisted(() => ({ id: 'u-bob' }))
const api = vi.hoisted(() => ({
  approveWorkflowVersion: vi.fn(),
  previewWorkflow: vi.fn(),
  validateWorkflow: vi.fn(),
  publishWorkflow: vi.fn(),
  setWorkflowSimulate: vi.fn(),
  invalidateWorkflowsCache: vi.fn(),
}))
const toast = vi.hoisted(() => ({ error: vi.fn(), success: vi.fn() }))

vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) =>
    p === 'automations:publish' ? perms.publish : p === 'automations:write' ? perms.write : false,
}))
vi.mock('@/stores/auth-store', () => ({ useUser: () => me }))
vi.mock('@/lib/api/workflow-hooks', () => ({
  ...api,
  useWorkflowVersions: () => ({ data: { items: [] }, isLoading: false, mutate: vi.fn() }),
  rollbackWorkflowVersion: vi.fn(),
}))
vi.mock('sonner', () => ({ toast }))

function wf(over: Partial<Workflow> = {}): Workflow {
  return {
    id: 'w1',
    tenant_id: 't1',
    name: 'KEV response',
    is_active: true,
    total_runs: 0,
    successful_runs: 0,
    failed_runs: 0,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    mode: 'simulate',
    risk_class: 'low',
    ...over,
  }
}

function bar(
  w: Workflow,
  extra: Partial<React.ComponentProps<typeof AutomationLifecycleBar>> = {}
) {
  return render(
    <AutomationLifecycleBar
      workflow={w}
      dirty={false}
      getDraft={() => ({ nodes: [], edges: [] })}
      validation={null}
      onPreview={vi.fn()}
      onValidate={vi.fn()}
      {...extra}
    />
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  perms.write = true
  perms.publish = true
  api.validateWorkflow.mockResolvedValue({ problems: [], warnings: [] })
})

describe('Before going live', () => {
  it('low risk needs only the publish permission', () => {
    render(<GoLiveChecks workflow={wf({ risk_class: 'low' })} validation={null} dirty={false} />)
    const checks = screen.getByTestId('golive-checks')
    expect(checks).toHaveTextContent('Risk class: Low')
    expect(checks.querySelector('[data-check="stepup"]')).toBeNull()
    expect(checks.querySelector('[data-check="approver"]')).toBeNull()
  })

  it('elevated risk needs a fresh sign-in', () => {
    render(
      <GoLiveChecks workflow={wf({ risk_class: 'elevated' })} validation={null} dirty={false} />
    )
    const checks = screen.getByTestId('golive-checks')
    expect(checks).toHaveTextContent('Going live needs a fresh sign-in')
    expect(checks.querySelector('[data-check="approver"]')).toBeNull()
  })

  it('high risk needs a fresh sign-in and a second publisher', () => {
    render(<GoLiveChecks workflow={wf({ risk_class: 'high' })} validation={null} dirty={false} />)
    const checks = screen.getByTestId('golive-checks')
    expect(checks).toHaveTextContent('Going live needs a fresh sign-in')
    expect(checks).toHaveTextContent('a second publisher approves this version')
  })

  it('says to save first and counts blocking problems', () => {
    render(
      <GoLiveChecks
        workflow={wf()}
        validation={{ problems: [{ code: 'GRAPH_CYCLE', message: 'x' }], warnings: [] }}
        dirty
      />
    )
    const checks = screen.getByTestId('golive-checks')
    expect(checks).toHaveTextContent('Save the draft before going live.')
    expect(checks).toHaveTextContent('1 problems block going live')
  })
})

describe('AutomationLifecycleBar', () => {
  it('shows the version line and unpublished changes', () => {
    bar(
      wf({
        mode: 'live',
        draft_changed: true,
        published_version: {
          id: 'v3',
          version: 3,
          digest: 'd3',
          risk_class: 'elevated',
          published_by: 'u-carol',
          published_by_name: 'Carol',
          published_at: '2026-10-20T10:00:00Z',
        },
      })
    )
    expect(screen.getByTestId('version-line')).toHaveTextContent(
      /Version 3, published by Carol on .*2026/
    )
    expect(screen.getByTestId('unpublished-changes')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Publish changes/ })).toBeInTheDocument()
  })

  const pending = {
    id: 'v4',
    version: 4,
    digest: 'sha256:v4',
    risk_class: 'high' as const,
    published_by: 'u-alice',
    published_by_name: 'Alice',
    created_at: '2026-10-21T00:00:00Z',
  }

  it('lets another publisher approve the pending version with its digest', async () => {
    api.approveWorkflowVersion.mockResolvedValue(wf())
    bar(wf({ pending_version: pending }))
    expect(screen.getByTestId('pending-version')).toHaveTextContent('Published by Alice')
    fireEvent.click(screen.getByRole('button', { name: 'Approve version 4' }))
    await waitFor(() =>
      expect(api.approveWorkflowVersion).toHaveBeenCalledWith('w1', 'v4', 'sha256:v4')
    )
  })

  it('never offers the publisher to approve their own version', () => {
    me.id = 'u-alice'
    bar(wf({ pending_version: pending }))
    expect(screen.queryByRole('button', { name: /Approve version/ })).toBeNull()
    expect(screen.getByTestId('pending-version')).toHaveTextContent(
      'Another person with publish rights must approve it.'
    )
    me.id = 'u-bob'
  })

  it('offers no approval without the publish permission', () => {
    perms.publish = false
    bar(wf({ pending_version: pending }))
    expect(screen.queryByRole('button', { name: /Approve version/ })).toBeNull()
    expect(screen.getByRole('button', { name: /Go live/ })).toBeDisabled()
  })

  it('disables preview and validate without the write permission', () => {
    perms.write = false
    bar(wf())
    expect(screen.getByRole('button', { name: /Preview/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Validate/ })).toBeDisabled()
  })

  it('translates a rate-limited preview', async () => {
    api.previewWorkflow.mockRejectedValue(new ApiClientError('rate limited', 'RATE_LIMITED', 429))
    const onPreview = vi.fn()
    bar(wf(), { onPreview })
    fireEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        'One preview every 10 seconds. Try again in a moment.'
      )
    )
    expect(onPreview).not.toHaveBeenCalled()
  })

  it('previews the unsaved draft with the chosen limit', async () => {
    const res = { subjects: 20, steps: [], deliveries: [] }
    api.previewWorkflow.mockResolvedValue(res)
    const onPreview = vi.fn()
    bar(wf(), { onPreview })
    fireEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(onPreview).toHaveBeenCalledWith(res))
    expect(api.previewWorkflow).toHaveBeenCalledWith('w1', { limit: 20, nodes: [], edges: [] })
  })

  it('opens Before going live, validates, and publishes for approval when high risk', async () => {
    api.publishWorkflow.mockResolvedValue({
      status: 'pending_approval',
      version: { id: 'v5', version: 5 },
    })
    bar(wf({ risk_class: 'high' }), {
      validation: { problems: [], warnings: [] },
    })
    fireEvent.click(screen.getByRole('button', { name: /Go live/ }))
    await waitFor(() => expect(api.validateWorkflow).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Publish for approval' }))
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        'Version 5 waits for a second publisher to approve it.'
      )
    )
  })

  it('switches a live automation to simulate in one click', async () => {
    api.setWorkflowSimulate.mockResolvedValue(wf())
    bar(wf({ mode: 'live' }))
    fireEvent.click(screen.getByRole('button', { name: 'Simulate' }))
    await waitFor(() => expect(api.setWorkflowSimulate).toHaveBeenCalledWith('w1'))
  })

  it('explains an automation switched off for a removed type', () => {
    bar(wf({ disabled_reason: 'uses_removed_type', is_active: false }))
    expect(screen.getByRole('status')).toHaveTextContent('Removed type')
  })
})
