/**
 * The rule editor (RFC-073 §4.1): conditions as removable chips with their
 * editors, the requirement form, and trying a draft on existing scans
 * without saving it. The rule list reorders by the arrow buttons.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ScanApprovalRule } from '@/lib/api/scan-approval-hooks'

const api = vi.hoisted(() => ({ test: vi.fn() }))
vi.mock('@/lib/api/scan-approval-hooks', () => ({ testScanGovernanceRules: api.test }))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ groups: [{ id: 'g1', name: 'Ops' }] }),
}))
vi.mock('@/features/access-control/api/use-roles', () => ({ useRoles: () => ({ roles: [] }) }))
vi.mock('@/features/service-accounts/api/use-service-accounts', () => ({
  useServiceAccounts: () => ({ data: { data: [{ id: 'sa1', name: 'CI bot' }] } }),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => ({ useScanZones: () => ({ data: { data: [] } }) }))
vi.mock('@/components/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { ApprovalRuleEditor } = await import('../approval-rule-editor')
const { ApprovalRuleList } = await import('../approval-rule-list')

function rule(over: Partial<ScanApprovalRule> = {}): ScanApprovalRule {
  return {
    id: 'r1',
    name: 'Intrusive scans',
    enabled: true,
    conditions: { min_intensity: 'intrusive', origins: ['api_key'] },
    requirement: { approvals: 1 },
    ...over,
  }
}

beforeEach(() => {
  api.test.mockReset()
})

describe('ApprovalRuleEditor', () => {
  it('shows each condition as a chip, removes one, and saves the edited rule', async () => {
    const onSave = vi.fn()
    const user = userEvent.setup()
    render(<ApprovalRuleEditor open rule={rule()} onOpenChange={() => {}} onSave={onSave} />)
    expect(screen.getByText('Intensity intrusive or above')).toBeInTheDocument()
    expect(screen.getByText('Through: Personal API key')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Remove Origin' }))
    expect(screen.queryByText('Through: Personal API key')).not.toBeInTheDocument()
    await user.click(screen.getByLabelText('Justification'))
    await user.click(screen.getByRole('button', { name: 'Save rule' }))
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({
        conditions: { min_intensity: 'intrusive' },
        requirement: expect.objectContaining({ require_justification: true }),
      })
    )
  })

  it('refuses to save without a name', async () => {
    render(
      <ApprovalRuleEditor
        open
        rule={rule({ name: '' })}
        onOpenChange={() => {}}
        onSave={() => {}}
      />
    )
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeDisabled()
  })

  it('tries the draft alone on existing scans and saves nothing', async () => {
    api.test.mockResolvedValue({
      mode: 'on',
      tested: 3,
      caught: 1,
      monitored: 0,
      total: 3,
      truncated: false,
      per_rule: {},
      scans: [
        {
          scan_id: 's1',
          name: 'Web pentest',
          intensity: 'intrusive',
          evaluation: {
            mode: 'on',
            required: true,
            approvals: 1,
            matched: [{ id: 'r1', name: 'Intrusive scans', requirement: { approvals: 1 } }],
          },
        },
      ],
    })
    const onSave = vi.fn()
    const user = userEvent.setup()
    render(
      <ApprovalRuleEditor
        open
        rule={rule({ monitor: true })}
        onOpenChange={() => {}}
        onSave={onSave}
      />
    )
    await user.click(screen.getByRole('button', { name: 'Try it on existing scans' }))
    await waitFor(() => expect(screen.getByText('Web pentest')).toBeInTheDocument())
    expect(api.test).toHaveBeenCalledWith([
      expect.objectContaining({ id: 'r1', monitor: false, enabled: true }),
    ])
    expect(screen.getByText(/1 of 3 scans would wait for approval/)).toBeInTheDocument()
    expect(onSave).not.toHaveBeenCalled()
  })

  it('lists the organization service accounts for the trusted allowlist', async () => {
    const user = userEvent.setup()
    render(
      <ApprovalRuleEditor
        open
        rule={rule({
          conditions: { origins: ['service_account'], trusted_service_account_ids: [] },
        })}
        onOpenChange={() => {}}
        onSave={() => {}}
      />
    )
    const box = screen.getByText('Trusted service accounts').parentElement as HTMLElement
    await user.click(within(box).getByLabelText('CI bot'))
    expect(screen.getByText('Except: CI bot')).toBeInTheDocument()
  })
})

describe('ApprovalRuleList', () => {
  it('moves a rule with the arrow buttons', async () => {
    const onMove = vi.fn()
    const user = userEvent.setup()
    render(
      <ApprovalRuleList
        rules={[rule(), rule({ id: 'r2', name: 'Production' })]}
        mode="on"
        canEdit
        onMove={onMove}
        onEdit={() => {}}
        onChange={() => {}}
        onRemove={() => {}}
      />
    )
    expect(screen.getByRole('button', { name: 'Move Intrusive scans up' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Move Production up' }))
    expect(onMove).toHaveBeenCalledWith(1, 0)
  })

  it('shows no editing controls to a reader', () => {
    render(
      <ApprovalRuleList
        rules={[rule()]}
        mode="on"
        canEdit={false}
        onMove={() => {}}
        onEdit={() => {}}
        onChange={() => {}}
        onRemove={() => {}}
      />
    )
    expect(screen.queryByRole('button', { name: /Edit|Move|Reorder/ })).not.toBeInTheDocument()
  })
})
