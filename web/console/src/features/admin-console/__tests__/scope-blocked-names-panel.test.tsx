import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  grantScopeNameException,
  revokeScopeNameException,
  type ScopeBlockedNames,
  type ScopeNameException,
} from '../api/use-scope-blocked-names'
import { parseNames, ScopeBlockedNamesPanel } from '../components/scope-blocked-names-panel'
import { approvalActionLabel, approvalTargetLabel } from '../lib/approvals'
import { AdminApiError } from '@console/lib/admin-api/client'

const state = vi.hoisted(() => ({
  policy: null as unknown,
  items: [] as unknown[],
}))

vi.mock('../api/use-scope-blocked-names', () => ({
  useScopeBlockedNames: () => ({ data: state.policy, isLoading: false, mutate: vi.fn() }),
  useScopeNameExceptions: () => ({
    data: { items: state.items },
    isLoading: false,
    mutate: vi.fn(),
  }),
  saveScopeBlockedNames: vi.fn(),
  grantScopeNameException: vi.fn(),
  extendScopeNameException: vi.fn(),
  revokeScopeNameException: vi.fn(),
}))
vi.mock('../api/use-admin-organizations', () => ({
  useOrganizations: () => ({
    data: { data: [{ id: 'org-a', name: 'Org A', slug: 'org-a' }] },
  }),
}))
vi.mock('../api/use-console-factors', () => ({ useConsoleFactors: () => ({ data: undefined }) }))
vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'super_admin' }),
  useAdminOrNull: () => ({ role: 'super_admin' }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const policy = (over: Partial<ScopeBlockedNames> = {}): ScopeBlockedNames => ({
  government_rule: true,
  names: ['internal.example.com'],
  env_names: ['env.example.com'],
  max_exception_days: 365,
  second_approval: false,
  version: 2,
  ...over,
})

const exception: ScopeNameException = {
  id: 'ex-1',
  organization_id: 'org-a',
  organization_name: 'Org A',
  name: 'portal.example.gov.xx',
  include_subdomains: false,
  reason: 'bug bounty program',
  authorization_ref: 'letter 42',
  granted_by: 'owner@example.com',
  granted_at: '2026-11-01T00:00:00Z',
  expires_at: '2027-01-01T23:59:59Z',
  state: 'active',
}

beforeEach(() => {
  cleanup()
  vi.clearAllMocks()
  state.policy = policy()
  state.items = []
})

describe('ScopeBlockedNamesPanel', () => {
  it('shows the rule, the operator names, the server names and what never changes', () => {
    render(<ScopeBlockedNamesPanel canEdit />)
    expect(screen.getByRole('switch')).toBeChecked()
    expect(screen.getByDisplayValue('internal.example.com')).toBeInTheDocument()
    expect(screen.getByText('env.example.com')).toBeInTheDocument()
    expect(screen.getByText(/loopback, link-local and cloud metadata/)).toBeInTheDocument()
    expect(screen.queryByTestId('government-rule-off-warning')).not.toBeInTheDocument()
  })

  it('keeps a standing warning while the rule is off', () => {
    state.policy = policy({ government_rule: false })
    render(<ScopeBlockedNamesPanel canEdit />)
    expect(screen.getByTestId('government-rule-off-warning')).toBeInTheDocument()
  })

  it('offers no change to an administrator without the permission', () => {
    state.items = [exception]
    render(<ScopeBlockedNamesPanel canEdit={false} />)
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Grant exception' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument()
    expect(screen.getByText('portal.example.gov.xx')).toBeInTheDocument()
  })

  it('lists exceptions and revokes one with a reason and a code, the error in the footer', async () => {
    state.items = [exception]
    vi.mocked(revokeScopeNameException).mockRejectedValueOnce(
      new AdminApiError('the exception is revoked; grant a new one', 409, 'EXCEPTION_REVOKED')
    )
    render(<ScopeBlockedNamesPanel canEdit />)
    const row = screen.getByText('portal.example.gov.xx').closest('tr') as HTMLElement
    expect(within(row).getByText('Org A')).toBeInTheDocument()
    expect(within(row).getByText('letter 42')).toBeInTheDocument()
    await userEvent.click(within(row).getByRole('button', { name: 'Revoke' }))
    const dialog = await screen.findByRole('dialog')
    const confirm = within(dialog).getByRole('button', { name: 'Revoke' })
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'program ended')
    const code = within(dialog).getAllByRole('textbox').at(-1) as HTMLElement
    await userEvent.type(code, '123456')
    await userEvent.click(confirm)
    await waitFor(() =>
      expect(revokeScopeNameException).toHaveBeenCalledWith(
        'ex-1',
        { reason: 'program ended' },
        '123456'
      )
    )
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      'the exception is revoked; grant a new one'
    )
  })

  it('grants an exception for the picked organization', async () => {
    vi.mocked(grantScopeNameException).mockResolvedValueOnce(exception)
    render(<ScopeBlockedNamesPanel canEdit />)
    await userEvent.click(screen.getByRole('button', { name: 'Grant exception' }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Organization'), 'org')
    await userEvent.click(await within(dialog).findByRole('button', { name: /Org A/ }))
    await userEvent.type(within(dialog).getByLabelText('Domain'), 'portal.example.gov.xx')
    await userEvent.type(
      within(dialog).getByLabelText('Written authorisation (reference)'),
      'letter 42'
    )
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'bounty')
    const code = within(dialog).getAllByRole('textbox').at(-1) as HTMLElement
    await userEvent.type(code, '123456')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Grant exception' }))
    await waitFor(() => expect(grantScopeNameException).toHaveBeenCalledTimes(1))
    const [input, sentCode] = vi.mocked(grantScopeNameException).mock.calls[0]
    expect(input).toMatchObject({
      organization_id: 'org-a',
      name: 'portal.example.gov.xx',
      include_subdomains: false,
      authorization_ref: 'letter 42',
      reason: 'bounty',
    })
    expect(input.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(sentCode).toBe('123456')
  })
})

describe('blocked names helpers', () => {
  it('parses one name per line or comma', () => {
    expect(parseNames(' A.example.com \n\n b.example.com, c.example.com')).toEqual([
      'a.example.com',
      'b.example.com',
      'c.example.com',
    ])
  })

  it('labels the approval actions and targets', () => {
    const t = (_k: string, f: string, v?: Record<string, string | number>) =>
      f.replace(/\{(\w+)\}/g, (_, k: string) => String(v?.[k] ?? ''))
    expect(approvalActionLabel('scope_names.exception', t)).toBe(
      'Let an organization scan a government or military name'
    )
    expect(
      approvalTargetLabel(
        {
          target:
            '{"tenant":"t-1","name":"portal.example.gov.xx","subdomains":true,"expires":"2027-01-01"}',
        },
        t
      )
    ).toBe('*.portal.example.gov.xx for organization t-1 until 2027-01-01')
    expect(
      approvalTargetLabel({ target: 'off', action: 'scope_names.government_rule_off' }, t)
    ).toBe('Government and military names no longer blocked')
  })
})
