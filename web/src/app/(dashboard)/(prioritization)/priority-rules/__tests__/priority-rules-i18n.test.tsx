import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { I18nProvider } from '@/context/i18n-provider'
import PriorityRulesPage from '../page'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/priority-rules',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useHasPermission: () => true,
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/sla/api/use-sla-policies-api', () => ({
  useEffectiveSlaPolicy: () => ({ data: undefined }),
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))

const swr = vi.hoisted(() => ({ data: { data: [] as unknown[] } }))
vi.mock('swr', () => ({
  default: () => ({ data: swr.data, error: undefined, isLoading: false, mutate: vi.fn() }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const FORMER_ENGLISH = [
  'No priority rules yet',
  'Create a rule to override',
  'Tune risk scoring',
  'Create rule',
]

describe('Priority rules page i18n', () => {
  it('renders the page chrome and empty state in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <PriorityRulesPage />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { name: 'Quy tắc ưu tiên' })).toBeInTheDocument()
    expect(screen.getByText('Cách quy tắc được đánh giá')).toBeInTheDocument()
    expect(screen.getByText('Chưa có quy tắc ưu tiên')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Tìm quy tắc…')).toBeInTheDocument()
    expect(screen.getByText('Tạo quy tắc')).toBeInTheDocument()
    for (const en of FORMER_ENGLISH) expect(screen.queryByText(new RegExp(en))).toBeNull()
  })

  it('renders the create dialog in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <PriorityRulesPage />
      </I18nProvider>
    )
    fireEvent.click(screen.getByText('Tạo quy tắc'))
    expect(screen.getByText('Tạo quy tắc ưu tiên')).toBeInTheDocument()
    expect(screen.getByLabelText('Tên *')).toBeInTheDocument()
    expect(screen.getByText('Thêm điều kiện')).toBeInTheDocument()
    expect(screen.queryByText('Add condition')).toBeNull()
    expect(screen.queryByText('Create priority rule')).toBeNull()
  })
})
