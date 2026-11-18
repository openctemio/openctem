/**
 * Settings › Scanning › Scan identification on the settings page pattern:
 * one column of framed sections, one save bar, the same PATCH body as before,
 * view only below the owner, loading and load-failed states, Vietnamese copy.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nProvider } from '@/context/i18n-provider'

const update = vi.fn()
const mutate = vi.fn()
let canEdit = true
let state: { isLoading: boolean; isError: boolean; error?: unknown } = {
  isLoading: false,
  isError: false,
}
const LONG_UA = `acme-security-scan-${'x'.repeat(200)}`
let security: Record<string, unknown> = {}
const current = { settings: {} as object }

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canEdit,
}))
vi.mock('@/features/organization/api/use-tenant-settings', () => ({
  // One settings object per test (a new object on every render would reset the form forever).
  useTenantSettings: () => ({ settings: current.settings, ...state, mutate }),
  useUpdateSecuritySettings: () => ({ updateSecuritySettings: update, isUpdating: false }),
}))
vi.mock('@/features/organization/components/last-changed', () => ({
  LastChanged: () => <span>Last changed by owner@example.com</span>,
}))

import { ScanIdentificationSettings } from '../scan-identification-settings'

function open(locale: 'en' | 'vi' = 'en') {
  current.settings = { general: {}, branding: {}, security, etags: {} }
  return render(
    <I18nProvider locale={locale}>
      <ScanIdentificationSettings />
    </I18nProvider>
  )
}

describe('Settings › Scan identification', () => {
  beforeEach(() => {
    update.mockReset()
    update.mockResolvedValue(undefined)
    mutate.mockReset()
    canEdit = true
    state = { isLoading: false, isError: false }
    security = {
      tool_http_user_agent: LONG_UA,
      tool_http_user_agents: [],
      tool_http_headers: [{ name: 'X-Scan-Team', value: 'red-team' }],
      tool_http_query: { name: '', value: '' },
      tool_http_identification_required: false,
      platform_scan_identification: {
        user_agent: 'platform-scan/1.0',
        user_agents: ['ua-a', 'ua-b'],
        user_agent_enforced: false,
        headers: [
          { name: 'X-Platform', value: 'on', enforced: true },
          { name: 'X-Hint', value: 'maybe', enforced: false },
        ],
        query: { name: 'scan', value: 'corp-1' },
        query_enforced: false,
      },
    }
  })

  it('draws three framed sections in one column with the last-changed line', () => {
    open()
    expect(screen.getByRole('heading', { level: 1, name: 'Scan identification' })).toBeVisible()
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings).toEqual(['Requirement', 'What your scans send', 'What a target receives'])
    expect(screen.getByText('Last changed by owner@example.com')).toBeInTheDocument()
    // The anchors the settings search points at still exist.
    for (const id of ['user-agent', 'headers', 'preview']) {
      expect(document.getElementById(id)).not.toBeNull()
    }
  })

  it('ties the hint to the User-Agent field and shows the platform layer', () => {
    open()
    const ua = screen.getByLabelText('User-Agent of scan tools')
    expect(ua).toHaveValue(LONG_UA)
    expect(ua.getAttribute('aria-describedby')).toContain('scan-ident-ua-hint')
    expect(screen.getByText('platform-scan/1.0')).toBeInTheDocument()
    expect(screen.getByText(/rotation list of 2 User-Agents/)).toBeInTheDocument()
    const platform = screen.getByTestId('scan-ident-platform-headers')
    expect(within(platform).getByText('Enforced')).toBeInTheDocument()
    expect(within(platform).getByText('Default, yours replaces it')).toBeInTheDocument()
    expect(screen.getByLabelText('Require identification on every request')).not.toBeChecked()
  })

  it('shows no save bar at rest; a change shows it with what changed, Discard restores', async () => {
    const user = userEvent.setup()
    open()
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
    await user.click(screen.getByLabelText('Require identification on every request'))
    const bar = screen.getByRole('region', { name: 'Unsaved changes' })
    expect(bar).toHaveTextContent('1 unsaved change')
    await user.click(within(bar).getByRole('button', { name: 'What changes' }))
    expect(await screen.findByRole('dialog')).toHaveTextContent(
      'Require identification on every request'
    )
    await user.click(within(bar).getByRole('button', { name: 'Discard' }))
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
    expect(screen.getByLabelText('Require identification on every request')).not.toBeChecked()
  })

  it('saves the five identification fields in one PATCH, as before', async () => {
    const user = userEvent.setup()
    open()
    const ua = screen.getByLabelText('User-Agent of scan tools')
    await user.clear(ua)
    await user.type(ua, 'example-scan (+soc@example.com)')
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    expect(update).toHaveBeenCalledTimes(1)
    expect(update).toHaveBeenCalledWith({
      tool_http_user_agent: 'example-scan (+soc@example.com)',
      tool_http_user_agents: [],
      tool_http_headers: [{ name: 'X-Scan-Team', value: 'red-team' }],
      tool_http_query: { name: '', value: '' },
      tool_http_identification_required: false,
    })
  })

  it('keeps the changes and says so when the save fails', async () => {
    update.mockRejectedValue(new Error('boom'))
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText('Require identification on every request'))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    const bar = await screen.findByRole('region', { name: 'Unsaved changes' })
    expect(within(bar).getByRole('alert')).toHaveTextContent(
      "Couldn't save. Your changes are kept."
    )
    expect(screen.getByLabelText('Require identification on every request')).toBeChecked()
  })

  it('refuses a User-Agent that is not printable ASCII, tied to the field', async () => {
    const user = userEvent.setup()
    open()
    const ua = screen.getByLabelText('User-Agent of scan tools')
    await user.clear(ua)
    await user.type(ua, 'quét-bảo-mật')
    expect(ua).toHaveAttribute('aria-invalid', 'true')
    expect(ua.getAttribute('aria-describedby')).toContain('scan-ident-ua-error')
    expect(screen.getByRole('button', { name: /Save changes/ })).toBeDisabled()
  })

  it('names the fix when identification is required without a marker', async () => {
    security = {
      ...security,
      tool_http_headers: [],
      platform_scan_identification: {
        user_agent: '',
        user_agent_enforced: false,
        headers: [],
      },
    }
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText('Require identification on every request'))
    const alert = screen.getByTestId('scan-ident-required-missing')
    await user.click(within(alert).getByRole('button', { name: 'Add header' }))
    expect(document.getElementById('scan-ident-name-0')).not.toBeNull()
  })

  it('locks the switch on when the platform requires identification', () => {
    security = {
      ...security,
      platform_scan_identification: {
        ...(security.platform_scan_identification as object),
        identification_required: true,
      },
    }
    open()
    const sw = screen.getByLabelText('Require identification on every request')
    expect(sw).toBeChecked()
    expect(sw).toBeDisabled()
    expect(screen.getByText('Required by: the platform')).toBeInTheDocument()
  })

  it('is view only below the owner: notice, disabled controls, no save bar', () => {
    canEdit = false
    open()
    expect(
      screen.getByText('Only the organization owner can change these settings.')
    ).toBeInTheDocument()
    expect(screen.getByLabelText('User-Agent of scan tools')).toBeDisabled()
    expect(screen.getByLabelText('Require identification on every request')).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Save changes/ })).toBeNull()
  })

  it('shows the loading skeleton, then a load failure with Retry (never defaults)', async () => {
    state = { isLoading: true, isError: false }
    const { unmount } = open()
    expect(screen.getByLabelText('Loading Scan identification')).toHaveAttribute(
      'aria-busy',
      'true'
    )
    expect(screen.queryByLabelText('User-Agent of scan tools')).toBeNull()
    unmount()
    state = { isLoading: false, isError: true, error: new Error('down') }
    open()
    expect(screen.getByText("Couldn't load Scan identification")).toBeInTheDocument()
    expect(screen.queryByLabelText('User-Agent of scan tools')).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }))
    expect(mutate).toHaveBeenCalled()
  })

  it('renders the Vietnamese catalog', () => {
    open('vi')
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings[0]).toBe('Yêu cầu')
    expect(headings).not.toContain('What your scans send')
  })
})
