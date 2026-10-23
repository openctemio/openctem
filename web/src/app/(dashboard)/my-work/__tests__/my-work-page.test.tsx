import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import MyWorkPage from '../page'
import en from '@/lib/i18n/dictionaries/en/myWork.json'
import viDict from '@/lib/i18n/dictionaries/vi/myWork.json'

const mockUseFindingsApi = vi.fn()
let locale = 'en'
const push = vi.fn()

vi.mock('@/features/findings/api/use-findings-api', async (orig) => ({
  ...(await orig<object>()),
  useFindingsApi: (f: unknown, c: unknown) => mockUseFindingsApi(f, c),
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    locale,
    t: (k: string, fb?: string, vars?: Record<string, string | number>) => {
      const dict = (locale === 'vi' ? viDict : en) as Record<string, string>
      let s = dict[k] ?? (typeof fb === 'string' ? fb : k)
      for (const [n, v] of Object.entries(vars ?? {})) s = s.replace(`{${n}}`, String(v))
      return s
    },
  }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => false }),
}))
vi.mock('@/features/remediation-hub/components/my-tasks-queue', () => ({
  MyTasksQueue: () => null,
  useMyTaskCount: () => undefined,
}))
vi.mock('@/features/findings/components/priority-class-badge', () => ({
  PriorityClassBadge: ({ priorityClass }: { priorityClass: string }) => (
    <span data-testid="prio">{priorityClass}</span>
  ),
}))

const finding = {
  id: 'f-1',
  title: 'SQL injection',
  severity: 'high',
  status: 'new',
  priority_class: 'P0',
  created_at: new Date(Date.now() - 3 * 86400_000).toISOString(),
  asset: { id: 'a-1', name: 'api.example.com', type: 'domain' },
}

function ok(total: number, data: unknown[] = []) {
  return { data: { total, data }, error: undefined, isLoading: false, mutate: vi.fn() }
}

describe('My work page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    locale = 'en'
  })

  it('renders the title as a link to the finding and a Priority column first, Created last', () => {
    mockUseFindingsApi.mockReturnValue(ok(1, [finding]))
    render(<MyWorkPage />)
    expect(screen.getByRole('link', { name: 'SQL injection' })).toHaveAttribute('href', '/findings/f-1')
    expect(screen.getByTestId('prio')).toHaveTextContent('P0')
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers[0]).toBe('Priority')
    expect(headers[headers.length - 1]).toBe('Created')
  })

  it('shows an error state with Retry and dashes, not zeros, when the requests fail', () => {
    const mutate = vi.fn()
    mockUseFindingsApi.mockReturnValue({ data: undefined, error: new Error('boom'), isLoading: false, mutate })
    render(<MyWorkPage />)
    expect(screen.queryByText(en['myWork.emptyTitle'])).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry|try again/i })).toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(3)
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('labels the first figure "Open · mine"', () => {
    mockUseFindingsApi.mockReturnValue(ok(2, [finding]))
    render(<MyWorkPage />)
    expect(screen.getByText('Open · mine')).toBeInTheDocument()
  })

  it('shows relative times in Vietnamese in the vi locale', () => {
    locale = 'vi'
    mockUseFindingsApi.mockReturnValue(ok(1, [finding]))
    render(<MyWorkPage />)
    expect(screen.getByText(/3 ngày/)).toBeInTheDocument()
    expect(screen.queryByText(/days ago/)).not.toBeInTheDocument()
  })
})
