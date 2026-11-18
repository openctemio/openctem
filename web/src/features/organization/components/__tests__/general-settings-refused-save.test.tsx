/**
 * Settings › General: a refused save marks the field it was about. The API's
 * validation details name the field when they can; a refusal without a field
 * (409 "name already used") is about the one field the request carried. The
 * message shows under that field (no toast over the page title), and the bar
 * keeps the changes.
 */
import { forwardRef } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nProvider } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'

const updateTenant = vi.fn()
const updateGeneral = vi.fn()
const toastError = vi.fn()
const current = { settings: {} as object }

vi.mock('sonner', () => ({ toast: { error: (m: string) => toastError(m), success: vi.fn() } }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings/general',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({
    currentTenant: { id: 't1', name: 'Example Org', slug: 'example-org' },
    updateCurrentTenant: vi.fn(),
    refreshTenants: vi.fn(),
  }),
}))
vi.mock('@/hooks/use-app-origin', () => ({ useAppHost: () => 'app.example.com' }))
vi.mock('@/hooks/use-url-param', () => ({ useUrlFilter: () => ['general', vi.fn()] }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useCanMutate: () => true,
  usePermissions: () => ({ isOwner: () => true, can: () => true }),
}))
vi.mock('@/features/organization/api/use-tenant-settings', () => ({
  useTenantSettings: () => ({
    settings: current.settings,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useUpdateTenant: () => ({ updateTenant, isUpdating: false }),
  useUpdateGeneralSettings: () => ({ updateGeneralSettings: updateGeneral, isUpdating: false }),
  useUpdateBrandingSettings: () => ({ updateBrandingSettings: vi.fn(), isUpdating: false }),
}))
vi.mock('@/features/organization/hooks/use-tenant-logo', () => ({
  useTenantLogo: () => ({ logoSrc: undefined, updateLogo: vi.fn() }),
}))
vi.mock('@/features/tenant/components/region-note', () => ({ OrganizationRegion: () => null }))
vi.mock('../dashboard-data-card', () => ({ DashboardDataCard: () => null }))
vi.mock('../delete-organization', () => ({ DeleteOrganizationItem: () => null }))
vi.mock('../storage-config-card', () => ({
  StorageConfigSection: forwardRef(function Storage() {
    return null
  }),
}))

import { GeneralSettings } from '../general-settings'

function open() {
  current.settings = {
    general: { timezone: 'UTC', language: 'en', industry: '', website: '' },
    branding: {},
  }
  return render(
    <I18nProvider locale="en">
      <GeneralSettings />
    </I18nProvider>
  )
}

describe('Settings › General refused save', () => {
  beforeEach(() => {
    updateTenant.mockReset()
    updateGeneral.mockReset()
    toastError.mockReset()
  })

  it('marks the one field the refused request carried, keeps the edit, and does not toast', async () => {
    updateTenant.mockRejectedValue(
      new ApiClientError('The organization name is already used', 'CONFLICT', 409)
    )
    const user = userEvent.setup()
    open()
    const name = screen.getByLabelText('Organization name')
    await user.clear(name)
    await user.type(name, 'Taken Org')
    await user.click(screen.getByRole('button', { name: /save/i }))

    const alerts = await screen.findAllByRole('alert')
    expect(alerts.some((a) => a.textContent === 'The organization name is already used')).toBe(true)
    expect(name).toHaveAttribute('aria-invalid', 'true')
    expect(name).toHaveValue('Taken Org')
    expect(toastError).not.toHaveBeenCalled()

    // Editing the field clears its mark.
    await user.type(name, 's')
    expect(name).not.toHaveAttribute('aria-invalid')
  })

  it('marks the field the API names among several sent', async () => {
    updateGeneral.mockRejectedValue(
      new ApiClientError('Invalid', 'VALIDATION_ERROR', 400, {
        errors: [{ field: 'website', message: 'must be an http or https address' }],
      })
    )
    const user = userEvent.setup()
    open()
    await user.type(screen.getByLabelText('Website'), 'ftp://example.com')
    await user.click(screen.getByRole('button', { name: /save/i }))
    await screen.findAllByRole('alert')
    expect(screen.getByLabelText('Website')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByLabelText('Organization name')).not.toHaveAttribute('aria-invalid')
  })
})
