/**
 * The integrations landing and SIEM pages are translated: no raw
 * "integrationsHub.*" / "siemIntegration.*" key reaches the screen in either
 * language, and the Vietnamese catalog differs from the English one.
 */
import { describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/components/link', () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  Permission: { IntegrationsRead: 'integrations:read' },
}))
vi.mock('@/features/repositories/hooks/use-repositories', () => ({
  useSCMConnections: () => ({ data: [] }),
}))
const integrations = [
  {
    id: '1',
    name: 'Prod Splunk',
    category: 'notification',
    provider: 'splunk',
    status: 'connected',
    metadata: { hec_url: 'https://s:8088', index: 'main' },
  },
  { id: '2', name: 'Jira', category: 'ticketing', provider: 'jira', status: 'expired' },
]
vi.mock('@/features/integrations/api', () => ({
  useIntegrationsApi: () => ({
    data: { data: integrations },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('@/features/integrations', () => ({
  useNotificationIntegrationsApi: () => ({
    data: { data: integrations },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCreateNotificationIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateNotificationIntegrationsCache: vi.fn(),
}))
vi.mock('@/lib/api/client', () => ({ csrfFetch: vi.fn(), del: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import IntegrationsPage from '../page'
import SIEMIntegrationPage from '../siem/page'

const RAW_KEY = /\b(integrationsHub|siemIntegration)\.[A-Za-z.-]+/

describe.each([
  ['landing', IntegrationsPage],
  ['siem', SIEMIntegrationPage],
])('%s page', (_name, Page) => {
  const text = (locale: string) => {
    const { container, unmount } = render(
      <I18nProvider locale={locale}>
        <Page />
      </I18nProvider>
    )
    const out = container.textContent ?? ''
    unmount()
    return out
  }

  it('resolves every key in en and vi', () => {
    expect(text('en')).not.toMatch(RAW_KEY)
    expect(text('vi')).not.toMatch(RAW_KEY)
  })

  it('renders Vietnamese differently from English', () => {
    expect(text('vi')).not.toEqual(text('en'))
  })
})

describe('landing page copy', () => {
  it('translates the metrics and the category cards', () => {
    const { container } = render(
      <I18nProvider locale="vi">
        <IntegrationsPage />
      </I18nProvider>
    )
    expect(container.textContent).toContain('Tổng số tích hợp')
    expect(container.textContent).toContain('Quản lý mã nguồn')
    expect(container.textContent).toContain('Đã hết hạn')
  })
})
