/**
 * The suggestion panel gives the basis to decide: the fix with the installed
 * versions, every finding with its location and rule, the grouping factors in
 * words (the key only under technical details), what accepting creates, and
 * findings left out by unticking them. Scanner text is plain text.
 */

import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { RemediationSuggestion, SuggestionMember } from '../api/types'

const members: SuggestionMember[] = [
  {
    finding_id: 'f1',
    role: 'primary',
    join_source: '',
    title: 'Django SQL injection',
    severity: 'high',
    status: 'new',
    priority_class: 'P1',
    asset_id: 'a1',
    asset_name: 'shop-api',
    asset_criticality: 'high',
    file_path: 'requirements.txt',
    start_line: 12,
    rule_id: 'CVE-2024-1234',
    installed_version: '3.2.1',
    fix_code: '<img src=x onerror=alert(1)>',
    verified: false,
    sla_deadline: '2026-11-01T00:00:00Z',
  },
  {
    finding_id: 'f2',
    role: 'primary',
    join_source: '',
    title: 'Django XSS',
    severity: 'medium',
    status: 'new',
    asset_id: 'a1',
    asset_name: 'shop-api',
    file_path: 'requirements.txt',
    start_line: 12,
    installed_version: '3.2.1',
    verified: false,
    active_task: { id: 't9', title: 'Patch shop' },
  },
]

// cmdk measures its list; jsdom has no ResizeObserver or scrollIntoView.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= function () {}

vi.mock('../api/use-remediation-hub', () => ({
  useSuggestionMembers: () => ({
    data: { data: members, total: 2, page: 1, per_page: 50 },
    isLoading: false,
  }),
}))
vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({
    users: [],
    groups: [],
    usersState: { allowed: true, loading: false, error: false },
    groupsState: { allowed: false, loading: false, error: false },
    user: () => undefined,
    group: (id?: string) => (id === 'g1' ? 'Payments team' : undefined),
  }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => false }),
}))

import { SuggestionPanel } from '../components/suggestion-panel'

const s: RemediationSuggestion = {
  id: 's1',
  kind: 'new_group',
  algorithm: 'deterministic',
  algorithm_version: 2,
  action_key: 'upgrade:pypi:django:4.2.30',
  key_kind: 'upgrade',
  title: 'Upgrade django to 4.2.30',
  partitions: [
    { owner_group_id: 'g1', owner_rule: 'asset_owner', finding_ids: ['f1', 'f2'], risk_points: 6 },
  ],
  member_count: 2,
  hidden_members: 0,
  truncated: 0,
  risk_points: 6,
  risk_parts: { p0: 0, p1: 1, p2: 1, p3: 0, unclassified: 0, kev: 0, assets: 1 },
  has_urgent: false,
  earliest_deadline: '2026-11-01T00:00:00Z',
  confidence: 1,
  fix_spec: {
    kind: 'upgrade',
    ecosystem: 'pypi',
    package: 'django',
    target_version: '4.2.30',
    basis: ['same_package_target'],
  },
  state: 'proposed',
  version: 3,
  created_at: '',
  updated_at: '',
}

function renderPanel(over: Partial<React.ComponentProps<typeof SuggestionPanel>> = {}) {
  const props = {
    suggestion: s,
    open: true,
    onOpenChange: vi.fn(),
    canWrite: true,
    canOwnerAccept: false,
    onAccept: vi.fn(),
    onEdit: vi.fn(),
    onDismiss: vi.fn(),
    onSnooze: vi.fn(),
    ...over,
  }
  render(<SuggestionPanel {...props} />)
  return props
}

describe('SuggestionPanel', () => {
  it('shows the fix with the installed versions and a major version warning', () => {
    renderPanel()
    const fix = screen.getByTestId('panel-fix')
    expect(fix).toHaveTextContent('django: 3.2.1 → 4.2.30')
    expect(fix).toHaveTextContent('Major version change')
    expect(fix).toHaveTextContent('pip install "django>=4.2.30"')
    // Scanner code is text, never markup.
    expect(fix).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(document.querySelector('img[src="x"]')).toBeNull()
  })

  it('lists every finding with its location, rule and the task that claimed it', () => {
    renderPanel()
    const list = screen.getByTestId('panel-findings')
    expect(list).toHaveTextContent('shop-api · requirements.txt:12')
    expect(list).toHaveTextContent('Rule CVE-2024-1234')
    expect(list).toHaveTextContent('Now in task "Patch shop"')
  })

  it('explains the grouping in words and keeps the key under technical details', () => {
    renderPanel()
    const why = screen.getByTestId('panel-why')
    expect(why).toHaveTextContent('same package to the same version')
    expect(why).toHaveTextContent('Exact: the findings share one fix identity (100%)')
    expect(within(why).getByText('Technical details')).toBeInTheDocument()
  })

  it('previews what accepting creates and sends the findings left out', async () => {
    const p = renderPanel()
    const preview = screen.getByTestId('accept-preview')
    expect(preview).toHaveTextContent('Creates 1 task:')
    expect(preview).toHaveTextContent('Task 1 · 2 findings')
    expect(preview).toHaveTextContent('Deadline:')
    const user = userEvent.setup()
    await user.click(screen.getByRole('checkbox', { name: 'Keep Django XSS' }))
    expect(screen.getByTestId('accept-preview')).toHaveTextContent('Task 1 · 1 finding')
    await user.click(screen.getByRole('button', { name: 'Accept with 1 finding' }))
    expect(p.onAccept).toHaveBeenCalledWith({ exclude_finding_ids: ['f2'] })
  })

  it('says why the team list is empty instead of showing nothing', async () => {
    renderPanel()
    await userEvent.setup().click(screen.getByRole('combobox', { name: 'Owner of task 1' }))
    expect(await screen.findByTestId('owner-notice-teams-forbidden')).toHaveTextContent(
      'You cannot see teams'
    )
  })

  it('offers an owner without write access only the as-is accept', () => {
    renderPanel({ canWrite: false, canOwnerAccept: true })
    expect(screen.getByRole('button', { name: 'Accept as owner' })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  })
})
