import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { AIRun } from '@/features/ai-triage/api/use-ai-agents'
import { FindingAIReviewSection } from '../finding-ai-review-section'

let runs: AIRun[] = []
let canRead = true
const runsHook = vi.fn()

vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: () => canRead }),
}))
vi.mock('@/features/ai-triage/api/use-ai-agents', async (orig) => ({
  ...(await orig<typeof import('@/features/ai-triage/api/use-ai-agents')>()),
  useFindingAIRuns: (id: string, enabled: boolean) => {
    runsHook(id, enabled)
    return { data: enabled ? runs : undefined }
  },
}))
let aiConfig: { mode: string; reason?: string } | undefined = { mode: 'platform' }
const swrKeys: unknown[] = []
vi.mock('swr', async (orig) => ({
  ...(await orig<typeof import('swr')>()),
  // The section reads the AI setup the bootstrap seeded, never fetching it.
  default: (key: unknown, fetcher: unknown) => {
    swrKeys.push([key, fetcher])
    return { data: aiConfig }
  },
}))

const base: AIRun = {
  id: 'r1',
  ai_agent_id: 'a1',
  ai_agent_name: 'Triage analyst',
  kind: 'triage.v1',
  executor: 'tenant_worker',
  sensor_id: 's1',
  status: 'completed',
  provider: 'example',
  model: 'example-model-1',
  model_family: 'example',
  outcome: 'applied',
  action_log: [
    { kind: 'verdict', outcome: 'applied' },
    { kind: 'severity', outcome: 'commented', reason: 'severity_needs_person' },
  ],
  trigger: 'schedule',
  accountable: [{ kind: 'user', id: 'u1', name: 'Owner Example' }],
  created_at: '2026-11-25T00:00:00Z',
  completed_at: '2026-11-25T00:01:00Z',
}

describe('FindingAIReviewSection', () => {
  beforeEach(() => {
    runs = [base]
    canRead = true
    aiConfig = { mode: 'platform' }
    runsHook.mockClear()
  })

  it('shows the AI mark, the review state, where it ran and each suggestion', () => {
    render(<FindingAIReviewSection findingId="f1" />)
    expect(screen.getByTestId('ai-badge')).toHaveAttribute('data-source', 'ai_agent')
    expect(screen.getByTestId('ai-review-state')).toHaveTextContent('Changed by AI')
    expect(screen.getByText('An AI worker of your organization')).toBeInTheDocument()
    expect(screen.getByText('A severity change needs a person')).toBeInTheDocument()
    expect(screen.getByText(/Owner Example/)).toBeInTheDocument()
  })

  it('says why a run was not reviewed', () => {
    runs = [
      {
        ...base,
        status: 'failed',
        outcome: undefined,
        action_log: [],
        error_code: 'deadline_exceeded',
      },
    ]
    render(<FindingAIReviewSection findingId="f1" />)
    expect(screen.getByTestId('ai-review-state')).toHaveTextContent('Not reviewed')
    expect(screen.getByText('Not reviewed: No answer before the deadline')).toBeInTheDocument()
  })

  it('renders worker-supplied names as text, never markup', () => {
    runs = [{ ...base, model: '<img src=x onerror=alert(1)>' }]
    const { container } = render(<FindingAIReviewSection findingId="f1" />)
    expect(container.querySelector('img')).toBeNull()
  })

  it('sends no request and shows nothing without ai_triage:read', () => {
    canRead = false
    const { container } = render(<FindingAIReviewSection findingId="f1" />)
    expect(runsHook).toHaveBeenCalledWith('f1', false)
    expect(container).toBeEmptyDOMElement()
  })

  it('names the AI agent from the run', () => {
    render(<FindingAIReviewSection findingId="f1" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Triage analyst')
  })

  it('reads the AI setup from the cache without a fetcher', () => {
    render(<FindingAIReviewSection findingId="f1" />)
    expect(swrKeys).toContainEqual(['/api/v1/findings/ai-triage/config', null])
  })

  it('sends no request while AI is off for the organization', () => {
    aiConfig = { mode: 'disabled', reason: 'not_enabled' }
    const { container } = render(<FindingAIReviewSection findingId="f1" />)
    expect(runsHook).toHaveBeenCalledWith('f1', false)
    expect(container).toBeEmptyDOMElement()
  })
})
