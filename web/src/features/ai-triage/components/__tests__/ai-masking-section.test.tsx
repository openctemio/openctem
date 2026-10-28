import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { toast } from 'sonner'

import { registerStepUpHandler } from '@/lib/api/step-up'
import { AIMaskingSection } from '../ai-masking-section'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const MASKING = '/api/v1/organization/settings/ai/masking'
const FINDING = '0b7c2c64-3a55-4b8e-9d8e-5d2f3c1a9e10'

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const CLASSES = ['hosts', 'ips', 'emails', 'users', 'url_params', 'orgs', 'tickets']
function policy(over: Record<string, unknown> = {}) {
  return {
    classes: CLASSES.map((c) => ({ class: c, masked: true })),
    mask_subdomain_labels: false,
    terms: ['Project Falcon'],
    max_terms: 200,
    ...over,
  }
}

type Handler = (init?: RequestInit) => Response
function route(fetchMock: ReturnType<typeof vi.fn>, handlers: Record<string, Handler>) {
  fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    const method = (init?.method ?? 'GET').toUpperCase()
    const path = new URL(url, 'http://localhost').pathname
    const h = handlers[`${method} ${path}`]
    return h ? h(init) : json(404, { code: 'NOT_FOUND', message: 'not found' })
  })
}

function renderSection(canEdit = true) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AIMaskingSection canEdit={canEdit} />
    </SWRConfig>
  )
}

describe('Settings > AI, data masking', () => {
  const fetchMock = vi.fn()
  let unregister: (() => void) | null = null

  beforeAll(() => {
    // Radix Select scrolls the selected option into view, which jsdom lacks.
    Element.prototype.scrollIntoView ??= () => {}
  })
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

  it('renders nothing until the API offers the masking policy (404)', async () => {
    route(fetchMock, {})
    const { container } = renderSection()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it('shows secrets as always masked and locked, and says restricted data is fully masked', async () => {
    route(fetchMock, { [`GET ${MASKING}`]: () => json(200, policy()) })
    renderSection()
    const secrets = await screen.findByRole('switch', { name: /Secrets/ })
    expect(secrets).toBeChecked()
    expect(secrets).toBeDisabled()
    expect(screen.getByText(/Always masked and never put back/)).toBeInTheDocument()
    expect(
      screen.getByText(/Restricted data \(code snippets\) is always sent with every class masked/)
    ).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'E-mail addresses' })).toBeEnabled()
    expect(screen.getByText(/can still point to your organization/)).toBeInTheDocument()
  })

  it('turning a class off asks first, then re-authenticates through step-up and retries', async () => {
    let puts = 0
    const bodies: string[] = []
    route(fetchMock, {
      [`GET ${MASKING}`]: () => json(200, policy()),
      [`PUT ${MASKING}`]: (init) => {
        puts++
        bodies.push(String(init?.body))
        return puts === 1
          ? json(403, { code: 'STEP_UP_REQUIRED', message: 'Confirm your identity' })
          : json(200, policy({ classes: CLASSES.map((c) => ({ class: c, masked: c !== 'ips' })) }))
      },
    })
    const stepUp = vi.fn(async () => true)
    unregister = registerStepUpHandler(stepUp)

    renderSection()
    await userEvent.click(await screen.findByRole('switch', { name: 'IP addresses and networks' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(puts).toBe(0)
    const dialog = screen.getByRole('alertdialog')
    expect(dialog).toHaveTextContent('Mask less?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(puts).toBe(2))
    expect(stepUp).toHaveBeenCalledTimes(1)
    expect(JSON.parse(bodies[0])).toEqual({
      off: ['ips'],
      mask_subdomain_labels: false,
      terms: ['Project Falcon'],
    })
    expect(bodies[1]).toBe(bodies[0])
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Data masking saved'))
  })

  it('removing a term asks first; adding one does not', async () => {
    let body = ''
    route(fetchMock, {
      [`GET ${MASKING}`]: () => json(200, policy()),
      [`PUT ${MASKING}`]: (init) => {
        body = String(init?.body)
        return json(200, policy({ terms: ['Project Falcon', 'Acme Bank'] }))
      },
    })
    renderSection()
    const input = await screen.findByLabelText('Extra terms to mask')
    await userEvent.type(input, 'ab')
    expect(screen.getByText('A term has 3 to 128 characters.')).toBeInTheDocument()
    await userEvent.clear(input)
    await userEvent.type(input, 'Acme Bank{Enter}')
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(screen.queryByRole('alertdialog')).toBeNull()
    await waitFor(() => expect(JSON.parse(body).terms).toEqual(['Project Falcon', 'Acme Bank']))

    await userEvent.click(await screen.findByRole('button', { name: 'Remove Project Falcon' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(screen.getByRole('alertdialog')).toBeInTheDocument()
  })

  it('previews a finding as plain text, with placeholders and their class only', async () => {
    const hostile = 'Host HOST_7QK2 says <img src=x onerror=alert(1)> [x](javascript:alert(1))'
    let previewBody = ''
    route(fetchMock, {
      [`GET ${MASKING}`]: () => json(200, policy()),
      [`POST ${MASKING}/preview`]: (init) => {
        previewBody = String(init?.body)
        return json(200, {
          text: hostile,
          placeholders: [
            { token: 'HOST_7QK2', class: 'HOST' },
            { token: 'SECRET_1', class: 'SECRET' },
          ],
          fields_sent: ['title', 'description'],
          fields_withheld: ['code_snippet'],
          data_class: 'internal',
        })
      },
    })
    renderSection()
    const preview = await screen.findByTestId('ai-masking-preview')
    const button = within(preview).getByRole('button', { name: 'Preview' })
    await userEvent.type(within(preview).getByLabelText('Finding id'), 'not-a-uuid')
    expect(button).toBeDisabled()
    await userEvent.clear(within(preview).getByLabelText('Finding id'))
    await userEvent.type(within(preview).getByLabelText('Finding id'), FINDING)
    await userEvent.click(button)

    const block = await within(preview).findByTestId('untrusted-text-block')
    expect(block).toHaveTextContent(hostile)
    expect(preview.querySelector('img')).toBeNull()
    expect(preview.querySelector('a')).toBeNull()
    expect(JSON.parse(previewBody)).toEqual({ finding_id: FINDING, data_class: 'internal' })
    const list = within(preview).getByTestId('ai-masking-placeholders')
    expect(within(list).getByText('HOST_7QK2')).toBeInTheDocument()
    expect(within(list).getByText('Internal host')).toBeInTheDocument()
    expect(within(list).getByText('Secret')).toBeInTheDocument()
    expect(within(preview).getByText('code_snippet')).toBeInTheDocument()
  })

  it('explains a preview the AI data policy refuses', async () => {
    route(fetchMock, {
      [`GET ${MASKING}`]: () => json(200, policy()),
      [`POST ${MASKING}/preview`]: () =>
        json(403, { code: 'AI_POLICY_RESTRICTED', message: 'restricted' }),
    })
    renderSection()
    const preview = await screen.findByTestId('ai-masking-preview')
    await userEvent.type(within(preview).getByLabelText('Finding id'), FINDING)
    await userEvent.click(within(preview).getByRole('button', { name: 'Preview' }))
    expect(await within(preview).findByRole('alert')).toHaveTextContent(
      /keeps this finding away from AI/
    )
  })

  it('is read-only for someone who may not change it', async () => {
    route(fetchMock, { [`GET ${MASKING}`]: () => json(200, policy()) })
    renderSection(false)
    expect(await screen.findByRole('switch', { name: 'E-mail addresses' })).toBeDisabled()
    expect(screen.queryByLabelText('Extra terms to mask')).toBeNull()
    expect(screen.queryByRole('button', { name: /Remove/ })).toBeNull()
  })
})
