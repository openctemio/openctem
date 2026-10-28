import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { ADMIN_STEP_UP_HEADER } from '@console/lib/admin-api/client'
import { AdminStepUpPrompt } from '../components/admin-step-up-prompt'
import { EmailSettingsForm } from '../components/email-settings-form'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

/**
 * A console form that carries its own step-up code (System > E-mail, with the
 * shell's step-up dialog mounted as in the console). A code the route refuses
 * (wrong, or already used) must come back to the form's own field: the
 * shell's step-up dialog must not open over the form's confirmation, where it
 * left the confirmation dimmed under a second overlay with its code field out
 * of reach and its Confirm button stuck.
 */

const stored = {
  enabled: true,
  host: 'smtp.example.com',
  port: 587,
  username: 'mailer',
  password_set: true,
  from: 'noreply@example.com',
  from_name: 'OpenCTEM',
  starttls: true,
  version: 3,
}

const FACTORS = {
  webauthn_enabled: false,
  authenticators: [],
  recovery_codes_left: 10,
  totp_enabled: true,
  totp_allowed: true,
  require_webauthn: false,
  enrollment_required: false,
  min_authenticators: 2,
  max_authenticators: 10,
}

type Call = { method: string; headers: Record<string, string>; body?: string }
let puts: Call[] = []
let putAnswers: Response[] = []

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status })
const refusedCode = () =>
  json(
    {
      code: 'ADMIN_STEP_UP_REQUIRED',
      message: 'Invalid or already used code; wait for your authenticator to show a new one',
    },
    401
  )

function route(url: string, init: RequestInit): Response {
  const method = init.method ?? 'GET'
  if (url.endsWith('/auth/factors')) return json(FACTORS)
  if (url.endsWith('/settings/email') && method === 'PUT') {
    puts.push({
      method,
      headers: init.headers as Record<string, string>,
      body: init.body as string,
    })
    return putAnswers.shift() ?? json({ ...stored, version: 4 })
  }
  return json({})
}

function renderPage(onSaved = vi.fn()) {
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <EmailSettingsForm settings={stored} canEdit onSaved={onSaved} />
      <AdminStepUpPrompt />
    </SWRConfig>
  )
  return onSaved
}

async function confirmWith(user: ReturnType<typeof userEvent.setup>, code: string) {
  const dialog = screen.getByRole('alertdialog')
  await user.type(within(dialog).getByLabelText('Code from your authenticator app'), code)
  await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))
}

describe('a console form whose step-up code is refused', () => {
  beforeEach(() => {
    puts = []
    putAnswers = []
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init: RequestInit) => Promise.resolve(route(url, init)))
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows the refusal in the form and saves with the next code, with no second dialog', async () => {
    const user = userEvent.setup()
    const onSaved = renderPage()
    await user.type(screen.getByLabelText('Password'), 'n3w-pass')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    putAnswers = [refusedCode()]
    await confirmWith(user, '123456')

    const dialog = screen.getByRole('alertdialog')
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/already used code/)
    // Only the form's own dialog: no step-up dialog stacked over it.
    expect(screen.queryByRole('dialog', { name: /Confirm it is you/ })).toBeNull()
    expect(document.querySelectorAll('[data-slot$="-overlay"]')).toHaveLength(1)
    // The field is cleared, enabled and focused for the next code; the
    // action is no longer pending.
    const field = within(dialog).getByLabelText('Code from your authenticator app')
    expect(field).toHaveValue('')
    expect(field).toBeEnabled()
    await waitFor(() => expect(field).toHaveFocus())
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeEnabled()

    await confirmWith(user, '654321')
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())
    expect(puts).toHaveLength(2)
    expect(puts[1].headers[ADMIN_STEP_UP_HEADER]).toBe('654321')
    expect(JSON.parse(puts[1].body ?? '{}')).toMatchObject({
      totp_code: '654321',
      password: 'n3w-pass',
    })
  })

  it('saves again after a save, then cancels and reopens cleanly', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.type(screen.getByLabelText('Password'), 'first')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await confirmWith(user, '111111')
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())

    await user.type(screen.getByLabelText('Password'), 'second')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Cancel' })
    )
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())
    expect(document.body.style.pointerEvents).not.toBe('none')

    await user.click(screen.getByRole('button', { name: 'Save' }))
    putAnswers = [refusedCode()]
    await confirmWith(user, '111111')
    expect(await within(screen.getByRole('alertdialog')).findByRole('alert')).toBeInTheDocument()
    await confirmWith(user, '222222')
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())
    expect(puts.map((p) => p.headers[ADMIN_STEP_UP_HEADER])).toEqual(['111111', '111111', '222222'])
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
