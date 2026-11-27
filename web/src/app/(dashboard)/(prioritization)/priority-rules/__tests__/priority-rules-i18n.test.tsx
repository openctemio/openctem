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

  it('reads stored conditions as plain sentences, never as code', () => {
    swr.data = {
      data: [
        {
          id: 'r1',
          name: 'Internet KEV',
          priority_class: 'P0',
          conditions: [
            { field: 'is_in_kev', operator: 'eq', value: true },
            { field: 'epss_score', operator: 'gte', value: 0.5 },
            { field: 'asset_exposure', operator: 'eq', value: 'private' },
            { field: 'severity', operator: 'in', value: ['critical', 'high'] },
          ],
          is_active: true,
          evaluation_order: 10,
          created_at: '2026-11-01T00:00:00Z',
          updated_at: '2026-11-01T00:00:00Z',
        },
      ],
    }
    render(
      <I18nProvider locale="vi">
        <PriorityRulesPage />
      </I18nProvider>
    )
    expect(screen.getAllByText('Có trong danh mục KEV').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Điểm EPSS từ 50% trở lên').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Mức độ phơi nhiễm của tài sản là Riêng tư').length).toBeGreaterThan(
      0
    )
    expect(screen.queryByText(/is_in_kev|epss_score|asset_exposure/)).toBeNull()
    swr.data = { data: [] }
  })
})
