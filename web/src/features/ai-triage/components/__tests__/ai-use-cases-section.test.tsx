import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { toast } from 'sonner'

import { registerStepUpHandler } from '@/lib/api/step-up'
import { AIUseCasesSection } from '../ai-use-cases-section'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const triage = {
  use_case: 'triage',
  mode: 'suggest',
  effective_mode: 'suggest',
  consented: true,
  executor: 'builtin',
  data_class_ceiling: 'internal',
  min_confidence: 0.85,
  triggers: ['on_demand'],
  budget_share: 100,
}

function list(over: Record<string, unknown> = {}) {
  return { data: [{ ...triage, ...over }], downgrade_threshold: 0.2, downgrade_window: 50 }
}

function renderSection(canEdit = true) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AIUseCasesSection canEdit={canEdit} />
    </SWRConfig>
  )
}

/** Routes the stubbed fetch by method and path. */
function route(fetchMock: ReturnType<typeof vi.fn>, handlers: Record<string, () => Response>) {
  fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    const method = (init?.method ?? 'GET').toUpperCase()
    const path = new URL(url, 'http://localhost').pathname
    const h = handlers[`${method} ${path}`]
    return h ? h() : json(404, { code: 'NOT_FOUND', message: 'not found' })
  })
}

describe('Settings > AI, use cases', () => {
  beforeAll(() => {
    // Radix Select scrolls the selected option into view, which jsdom lacks.
    Element.prototype.scrollIntoView ??= () => {}
  })

  const fetchMock = vi.fn()
  let unregister: (() => void) | null = null

  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    unregister?.()
    unregister = null
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('renders nothing until the API offers use cases (404)', async () => {
    route(fetchMock, {})
    const { container } = renderSection()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the fixed rules and, without consent, that the use case is not in effect', async () => {
    route(fetchMock, {
      'GET /api/v1/organization/settings/ai/use-cases': () =>
        json(200, list({ consented: false, effective_mode: 'off' })),
    })
    renderSection()
    expect(await screen.findByText('Use cases')).toBeInTheDocument()
    expect(screen.getByTestId('ai-use-case-triage-consent')).toHaveTextContent(
      /AI triage is off for this organization/
    )
    expect(screen.getByText(/Anything that lowers risk/)).toBeInTheDocument()
    expect(screen.getByText(/Severity changes always wait for a person/)).toBeInTheDocument()
    expect(screen.getByText(/Auto-apply only adds information/)).toBeInTheDocument()
  })

  it('turning auto-apply on asks first, then re-authenticates through step-up and retries', async () => {
    let puts = 0
    const bodies: string[] = []
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      const method = (init?.method ?? 'GET').toUpperCase()
      if (method === 'PUT' && url.includes('/use-cases/triage')) {
        puts++
        bodies.push(String(init?.body))
        return puts === 1
          ? json(403, { code: 'STEP_UP_REQUIRED', message: 'Confirm your identity' })
          : json(200, { ...triage, mode: 'auto_apply', effective_mode: 'auto_apply' })
      }
      if (url.includes('/use-cases')) return json(200, list())
      return json(404, { code: 'NOT_FOUND', message: 'x' })
    })
    const stepUp = vi.fn(async () => true)
    unregister = registerStepUpHandler(stepUp)

    renderSection()
    await userEvent.click(await screen.findByLabelText('Mode'))
    await userEvent.click(screen.getByRole('option', { name: 'Auto-apply' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    // Loosening asks for confirmation before any request.
    expect(puts).toBe(0)
    const dialog = screen.getByRole('alertdialog')
    expect(dialog).toHaveTextContent(/sign in again/)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(puts).toBe(2))
    expect(stepUp).toHaveBeenCalledTimes(1)
    expect(JSON.parse(bodies[0])).toEqual({ mode: 'auto_apply' })
    expect(bodies[1]).toBe(bodies[0])
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Use case saved'))
  })

  it('saves a tighter change without asking, and refuses a confidence out of range', async () => {
    let body = ''
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      if ((init?.method ?? 'GET').toUpperCase() === 'PUT') {
        body = String(init?.body)
        return json(200, { ...triage, min_confidence: 0.9 })
      }
      if (url.includes('/use-cases')) return json(200, list())
      return json(404, {})
    })
    renderSection()
    const input = await screen.findByLabelText('Minimum confidence to auto-apply')
    await userEvent.clear(input)
    await userEvent.type(input, '1.2')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await userEvent.clear(input)
    await userEvent.type(input, '0.9')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.queryByRole('alertdialog')).toBeNull()
    await waitFor(() => expect(JSON.parse(body)).toEqual({ min_confidence: 0.9 }))
  })

  it('explains an automatic downgrade and offers to turn auto-apply back on', async () => {
    route(fetchMock, {
      'GET /api/v1/organization/settings/ai/use-cases': () =>
        json(
          200,
          list({ downgraded_at: '2026-10-27T10:00:00Z', downgrade_reason: 'override_rate' })
        ),
    })
    renderSection()
    expect(await screen.findByText('Auto-apply was turned back to suggest')).toBeInTheDocument()
    expect(screen.getByText(/overrode 20% or more of the last 50 suggestions/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Turn auto-apply back on' }))
    expect(screen.getByRole('alertdialog')).toBeInTheDocument()
  })

  it('is read-only for someone who may not change it', async () => {
    route(fetchMock, {
      'GET /api/v1/organization/settings/ai/use-cases': () => json(200, list()),
    })
    renderSection(false)
    expect(await screen.findByText('Use cases')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
    expect(screen.getByLabelText('Mode')).toBeDisabled()
  })
})
