/** The exceptions list: strip counts, the ends-within filter, names instead of ids, permission-gated New. */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

const nav = vi.hoisted(() => ({ qs: '' }))
const perms = vi.hoisted(() => ({ write: true }))
const DAY = 24 * 60 * 60 * 1000
const iso = (days: number) => new Date(Date.now() + days * DAY).toISOString()
const rule = (over: Record<string, unknown>) => ({
  tenant_id: 't',
  suppression_type: 'false_positive',
  requested_by: 'u-req',
  requested_at: iso(-4),
  created_at: iso(-10),
  updated_at: iso(-10),
  ...over,
})
const rules = [
  rule({
    id: 'a',
    name: 'Ends soon',
    status: 'approved',
    approved_by: 'u-app',
    expires_at: iso(3),
  }),
  rule({ id: 'b', name: 'Ends this month', status: 'approved', expires_at: iso(20) }),
  rule({ id: 'c', name: 'Waiting one', status: 'pending', suppression_type: 'accepted_risk' }),
  rule({ id: 'd', name: 'Old one', status: 'expired', expires_at: iso(-2) }),
]

vi.mock('@/features/remediation-hub/api/use-owner-names', () => ({
  useOwnerNames: () => ({
    user: (id?: string) => ({ 'u-app': 'Alex Kim', 'u-req': 'Sam Rivera' })[id ?? ''],
  }),
}))
vi.mock('@/features/exceptions', async (orig) => ({
  ...(await orig<typeof import('@/features/exceptions')>()),
  useSuppressions: () => ({ data: { data: rules, total: rules.length }, mutate: vi.fn() }),
  useApproveSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
  useMarkSuppressionReviewed: () => ({ trigger: vi.fn() }),
  useRejectSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteSuppression: () => ({ trigger: vi.fn(), isMutating: false }),
  SuppressionFormDialog: () => null,
  SuppressionDetailSheet: () => null,
  SuppressionApprovePreview: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.write || !p.endsWith(':write') }),
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/exceptions',
  useSearchParams: () => new URLSearchParams(nav.qs),
}))
vi.mock('@/hooks/use-my-user-id', () => ({ useMyUserId: () => undefined }))

import { endsWithin } from '@/features/exceptions'
import ExceptionsPage from '../page'

const at = (qs: string) => {
  nav.qs = qs
  window.history.replaceState({}, '', qs ? `/exceptions?${qs}` : '/exceptions')
}

beforeEach(() => {
  at('')
  perms.write = true
})

describe('endsWithin', () => {
  it('counts only approved rules whose end is ahead and inside the window', () => {
    const now = Date.now()
    expect(endsWithin(rules[0] as never, 7, now)).toBe(true)
    expect(endsWithin(rules[1] as never, 7, now)).toBe(false)
    expect(endsWithin(rules[1] as never, 30, now)).toBe(true)
    expect(endsWithin(rules[3] as never, 30, now)).toBe(false)
  })
})

describe('Exceptions list', () => {
  it('shows people by name, never by id', () => {
    render(<ExceptionsPage />)
    expect(screen.getAllByText('Alex Kim').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Sam Rivera').length).toBeGreaterThan(0)
    expect(screen.queryByText(/u-req/)).not.toBeInTheDocument()
  })

  it('keeps only the rules ending within the window of the URL', () => {
    at('ends=7')
    render(<ExceptionsPage />)
    expect(screen.getAllByText('Ends soon').length).toBeGreaterThan(0)
    expect(screen.queryByText('Ends this month')).not.toBeInTheDocument()
    expect(screen.queryByText('Waiting one')).not.toBeInTheDocument()
  })

  it('filters by type from the URL', () => {
    at('type=accepted_risk')
    render(<ExceptionsPage />)
    expect(screen.getAllByText('Waiting one').length).toBeGreaterThan(0)
    expect(screen.queryByText('Ends soon')).not.toBeInTheDocument()
  })

  it('offers New exception only with the write permission', () => {
    perms.write = false
    render(<ExceptionsPage />)
    expect(screen.queryByRole('button', { name: 'New exception' })).not.toBeInTheDocument()
  })
})
