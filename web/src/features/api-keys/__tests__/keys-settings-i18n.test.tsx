import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/settings',
  useSearchParams: () => new URLSearchParams(),
}))

const mutate = vi.fn()
vi.mock('@/features/api-keys/api/use-api-keys', () => ({
  useApiKeys: () => ({ data: { data: [], total: 0 }, error: undefined, isLoading: false, mutate }),
  useCreateApiKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useRevokeApiKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteApiKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useApiKeyPolicy: () => ({
    data: { max_lifetime_days: 90, default_max_lifetime_days: 90, ceiling_days: 365 },
    mutate,
  }),
  updateApiKeyPolicy: vi.fn(),
}))
vi.mock('@/features/service-accounts/api/use-service-accounts', () => ({
  useServiceAccounts: () => ({ data: { data: [] }, error: undefined, isLoading: false, mutate }),
  useCreateServiceAccount: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteServiceAccount: () => ({ trigger: vi.fn(), isMutating: false }),
  useServiceAccountKeys: () => ({ data: { data: [] }, isLoading: false, mutate }),
  useCreateServiceAccountKey: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteServiceAccountKey: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('@/features/scim-tokens/api/use-scim-tokens', () => ({
  useScimTokens: () => ({ data: { tokens: [] }, isLoading: false, mutate }),
  useCreateScimToken: () => ({ trigger: vi.fn(), isMutating: false }),
  useRevokeScimToken: () => ({ trigger: vi.fn(), isMutating: false }),
  useRotateScimToken: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('@/features/organization/api/use-org-trusts', () => ({
  useOrgTrusts: () => ({ trusts: [], isLoading: false, error: undefined, mutate }),
  approveOrgTrust: vi.fn(),
  deleteOrgTrust: vi.fn(),
  createOrgTrust: vi.fn(),
  updateOrgTrust: vi.fn(),
}))
vi.mock('@/features/sso-approvals/api/use-sso-changes', () => ({
  useSSOChanges: () => ({ data: { changes: [] }, error: undefined, isLoading: false, mutate }),
  decideSSOChange: vi.fn(),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({
    isAdmin: () => true,
    isOwner: () => true,
    isAtLeast: () => true,
    isLoading: false,
  }),
  useCanMutate: () => true,
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

import APIKeysPage from '@/app/(dashboard)/settings/api-keys/page'
import ServiceAccountsPage from '@/app/(dashboard)/settings/service-accounts/page'
import ScimTokensPage from '@/app/(dashboard)/settings/scim/page'
import TrustedOrganizationsPage from '@/app/(dashboard)/settings/trusted-organizations/page'
import SSOApprovalsPage from '@/app/(dashboard)/settings/sso-approvals/page'

const vi_ = (ui: React.ReactNode) => render(<I18nProvider locale="vi">{ui}</I18nProvider>)

describe('API keys, service accounts, SCIM and trust settings in Vietnamese', () => {
  it('API keys page', () => {
    vi_(<APIKeysPage />)
    expect(screen.getAllByText('Tạo khóa API').length).toBeGreaterThan(0)
    expect(screen.getByText('Chưa có khóa API')).toBeInTheDocument()
    expect(screen.queryByText('No API keys yet')).toBeNull()
    expect(screen.queryByText('Generate API Key')).toBeNull()
  })

  it('service accounts page', () => {
    vi_(<ServiceAccountsPage />)
    expect(screen.getAllByText('Tài khoản dịch vụ').length).toBeGreaterThan(0)
    expect(screen.getByText('Chưa có tài khoản dịch vụ')).toBeInTheDocument()
    expect(screen.queryByText('No service accounts yet')).toBeNull()
  })

  it('SCIM page', () => {
    vi_(<ScimTokensPage />)
    // No strip of totals on a configuration inventory (research/244 §4): the
    // list itself counts the tokens.
    expect(screen.queryByText('Tổng số token')).toBeNull()
    expect(screen.getByText('Chưa có token SCIM')).toBeInTheDocument()
    expect(screen.queryByText('Total tokens')).toBeNull()
    expect(screen.queryByText('No SCIM tokens yet')).toBeNull()
  })

  it('trusted organizations page', () => {
    vi_(<TrustedOrganizationsPage />)
    expect(screen.getByText('Tổ chức bạn tin cậy')).toBeInTheDocument()
    expect(screen.getByText('Tin cậy một tổ chức')).toBeInTheDocument()
    expect(screen.queryByText('Trust an organization')).toBeNull()
  })

  it('SSO approvals page', () => {
    vi_(<SSOApprovalsPage />)
    expect(screen.getByText('Không có gì cần phê duyệt')).toBeInTheDocument()
    expect(screen.queryByText('Nothing to approve')).toBeNull()
  })
})
