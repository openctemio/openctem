import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { I18nProvider } from '@/context/i18n-provider'
import Page from '../page'

const getMock = vi.fn()
vi.mock('@/lib/api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api/client')>()),
  get: (...a: unknown[]) => getMock(...a),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  Can: ({ children }: { children: React.ReactNode }) => children,
}))
vi.mock('@/features/shared/components/gated-section-tabs', () => ({ GatedSectionTabs: () => null }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const renderPage = (locale: string) =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <I18nProvider locale={locale}>
        <Page />
      </I18nProvider>
    </SWRConfig>
  )

describe('business-units page header', () => {
  beforeEach(() => {
    getMock.mockReset()
    getMock.mockResolvedValue({ data: [], total: 0 })
  })

  it('names the icon-only Export button with an sr-only label at base width', async () => {
    renderPage('en')
    const label = await screen.findByText('Export')
    // Hidden visually below md, but still in the accessible name.
    expect(label.className).toContain('sr-only')
    expect(label.className).toContain('md:not-sr-only')
    expect(screen.getByRole('button', { name: 'Export' })).toBeTruthy()
  })

  it('renders the Vietnamese title, description and Export label', async () => {
    renderPage('vi')
    expect(await screen.findByRole('heading', { name: 'Đơn vị kinh doanh' })).toBeTruthy()
    expect(screen.getByText(/Cơ cấu tổ chức của bạn/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Xuất' }) ?? null).toBeTruthy()
    expect(screen.queryByText('Business units')).toBeNull()
  })
})
