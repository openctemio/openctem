/**
 * Settings › Scanning › Sensor job safety on the settings page pattern: the
 * scan-job switches save together through one save bar (loosening asks
 * first), the sensor key and shared-sensor switches apply at once in their
 * own section, view only below the owner, loading and load-failed states.
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
vi.mock('../sensor-opt-in-banner', () => ({ SensorOptInBanner: () => null }))
vi.mock('../sensor-identity-policy-switch', () => ({
  SensorIdentityPolicySwitch: () => <div data-testid="sensor-identity-policy" />,
}))
vi.mock('../sensor-key-bind-policy-switch', () => ({
  SensorKeyBindPolicySwitch: () => <div data-testid="sensor-key-bind-policy" />,
}))
vi.mock('../shared-sensors-opt-out-switch', () => ({
  SharedSensorsOptOutSwitch: () => <div data-testid="shared-sensors-opt-out" />,
}))

import { SensorJobSafetySettings } from '../sensor-job-safety-settings'

function open(locale: 'en' | 'vi' = 'en') {
  current.settings = { general: {}, branding: {}, security, etags: {} }
  return render(
    <I18nProvider locale={locale}>
      <SensorJobSafetySettings />
    </I18nProvider>
  )
}

const PRIVATE = 'Private targets need a sensor-local policy'

describe('Settings › Sensor job safety', () => {
  beforeEach(() => {
    update.mockReset()
    update.mockResolvedValue(undefined)
    mutate.mockReset()
    canEdit = true
    state = { isLoading: false, isError: false }
    security = {
      require_sensor_local_policy_for_private_targets: true,
      allow_sensor_interactsh: false,
      allow_sensor_custom_templates: false,
      forbid_tool_insecure_tls: true,
    }
  })

  it('draws two framed sections: the saved scan-job rules and the at-once switches', () => {
    open()
    expect(screen.getByRole('heading', { level: 1, name: 'Sensor job safety' })).toBeVisible()
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings).toEqual(['Scan jobs', 'Sensor keys and shared sensors'])
    const keys = screen.getByRole('region', { name: 'Sensor keys and shared sensors' })
    expect(within(keys).getByTestId('sensor-identity-policy')).toBeInTheDocument()
    expect(within(keys).getByTestId('sensor-key-bind-policy')).toBeInTheDocument()
    expect(within(keys).getByTestId('shared-sensors-opt-out')).toBeInTheDocument()
    for (const id of ['private-targets', 'opt-ins', 'tool-http', 'sensor-policies']) {
      expect(document.getElementById(id)).not.toBeNull()
    }
    expect(screen.getByRole('link', { name: 'Scan identification' })).toHaveAttribute(
      'href',
      '/settings/scanning/identification'
    )
  })

  it('shows every saved value on its labelled switch, hint tied', () => {
    open()
    const priv = screen.getByLabelText(PRIVATE)
    expect(priv).toBeChecked()
    expect(priv.getAttribute('aria-describedby')).toBeTruthy()
    expect(document.getElementById(priv.getAttribute('aria-describedby')!)).toHaveTextContent(
      /RFC 1918/
    )
    const switches = screen.getAllByRole('switch')
    expect(switches.map((s) => s.getAttribute('aria-checked'))).toEqual([
      'true',
      'false',
      'false',
      'true',
    ])
  })

  it('a tightening change saves at once through the bar, with the four fields', async () => {
    security.require_sensor_local_policy_for_private_targets = false
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText(PRIVATE))
    const bar = screen.getByRole('region', { name: 'Unsaved changes' })
    expect(bar).toHaveTextContent('1 unsaved change')
    await user.click(within(bar).getByRole('button', { name: /Save changes/ }))
    expect(update).toHaveBeenCalledWith({
      require_sensor_local_policy_for_private_targets: true,
      allow_sensor_interactsh: false,
      allow_sensor_custom_templates: false,
      forbid_tool_insecure_tls: true,
    })
  })

  it('a loosening change asks first and lists what widens', async () => {
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText(PRIVATE))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    expect(update).not.toHaveBeenCalled()
    const dialog = screen.getByRole('alertdialog')
    expect(dialog).toHaveTextContent('Private targets may go to sensors without a local policy.')
    await user.click(within(dialog).getByRole('button', { name: 'Save anyway' }))
    expect(update).toHaveBeenCalledTimes(1)
  })

  it('Discard restores the saved values', async () => {
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText(PRIVATE))
    await user.click(screen.getByRole('button', { name: 'Discard' }))
    expect(screen.getByLabelText(PRIVATE)).toBeChecked()
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
  })

  it('a failed save keeps the changes and says so in the bar', async () => {
    security.require_sensor_local_policy_for_private_targets = false
    update.mockRejectedValue(new Error('boom'))
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText(PRIVATE))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    const bar = await screen.findByRole('region', { name: 'Unsaved changes' })
    expect(within(bar).getByRole('alert')).toHaveTextContent(
      "Couldn't save. Your changes are kept."
    )
    expect(screen.getByLabelText(PRIVATE)).toBeChecked()
  })

  it('is view only below the owner', () => {
    canEdit = false
    open()
    expect(
      screen.getByText('Only the organization owner can change these settings.')
    ).toBeInTheDocument()
    expect(screen.getByLabelText(PRIVATE)).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Save changes/ })).toBeNull()
  })

  it('shows loading, then a load failure with Retry', async () => {
    state = { isLoading: true, isError: false }
    const { unmount } = open()
    expect(screen.getByLabelText('Loading Sensor job safety')).toBeInTheDocument()
    unmount()
    state = { isLoading: false, isError: true, error: new Error('down') }
    open()
    expect(screen.getByText("Couldn't load Sensor job safety")).toBeInTheDocument()
    expect(screen.queryByLabelText(PRIVATE)).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }))
    expect(mutate).toHaveBeenCalled()
  })

  it('renders the Vietnamese catalog', () => {
    open('vi')
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings).not.toContain('Scan jobs')
    expect(screen.queryByText(PRIVATE)).toBeNull()
  })
})
