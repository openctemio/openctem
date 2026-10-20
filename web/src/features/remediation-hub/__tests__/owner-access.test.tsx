/**
 * The owner picker explains missing access (counts only): a candidate the
 * viewer may not pick offers "Request access"; one the viewer may pick shows
 * the consent line.
 */

import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= function () {}

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => false }),
}))

import { OwnerCombobox } from '../components/owner-combobox'
import { ownerCandidatesUrl, type OwnerCandidates } from '../api/use-owner-access'

const access: OwnerCandidates = {
  findings: 3,
  candidates: [
    { type: 'user', id: 'u1', name: 'Hoa', missing_findings: 0, missing_assets: 0 },
    { type: 'user', id: 'u2', name: 'Sam', missing_findings: 3, missing_assets: 2 },
    {
      type: 'team',
      id: 'g1',
      name: 'Payments',
      missing_findings: 3,
      missing_assets: 2,
      members: 9,
      members_missing: 4,
    },
  ],
}

const people = [
  { id: 'u1', name: 'Hoa' },
  { id: 'u2', name: 'Sam' },
]
const teams = [{ id: 'g1', name: 'Payments' }]

describe('OwnerCombobox access explanation', () => {
  it('shows the gap and offers Request access when the viewer cannot assign', async () => {
    const onChange = vi.fn()
    const onRequest = vi.fn()
    render(
      <OwnerCombobox
        label="Owner"
        value={{}}
        onChange={onChange}
        users={people}
        groups={teams}
        access={access}
        canAssign={false}
        onRequestAccess={onRequest}
      />
    )
    const user = userEvent.setup()
    await user.click(screen.getByRole('combobox', { name: 'Owner' }))
    expect(await screen.findByTestId('owner-gap-u2')).toHaveTextContent(
      'Needs access to 3 findings on 2 assets'
    )
    expect(screen.getByTestId('owner-gap-g1')).toHaveTextContent('4 of 9 members')
    expect(screen.queryByTestId('owner-gap-u1')).not.toBeInTheDocument()
    // The entitled person can be picked; the one with a gap cannot.
    expect(screen.getByRole('option', { name: /Sam/ })).toHaveAttribute('aria-disabled', 'true')
    await user.click(screen.getAllByRole('button', { name: 'Request access' })[0])
    expect(onRequest).toHaveBeenCalledTimes(1)
    expect(onChange).not.toHaveBeenCalled()
  })

  it('asks for consent when the viewer may assign', async () => {
    const onConsent = vi.fn()
    render(
      <OwnerCombobox
        label="Owner"
        value={{ userId: 'u2' }}
        onChange={vi.fn()}
        users={people}
        groups={teams}
        access={access}
        canAssign
        consent={false}
        onConsentChange={onConsent}
      />
    )
    expect(screen.getByTestId('owner-consent')).toHaveTextContent('Sam will be able to see these 3 findings')
    await userEvent.setup().click(screen.getByRole('checkbox'))
    expect(onConsent).toHaveBeenCalledWith(true)
  })

  it('shows nothing extra for an owner who sees everything', () => {
    render(
      <OwnerCombobox
        label="Owner"
        value={{ userId: 'u1' }}
        onChange={vi.fn()}
        users={people}
        groups={teams}
        access={access}
        canAssign
      />
    )
    expect(screen.queryByTestId('owner-consent')).not.toBeInTheDocument()
  })
})

describe('ownerCandidatesUrl', () => {
  it('uses the task, or the findings of a new task', () => {
    expect(ownerCandidatesUrl({ taskId: 't1' }, ' sam ')).toBe(
      '/api/v1/remediation/tasks/t1/owner-candidates?q=sam'
    )
    expect(ownerCandidatesUrl({ findingIds: ['a', 'b'] }, '')).toBe(
      '/api/v1/remediation/tasks/owner-candidates?finding_ids=a%2Cb'
    )
    expect(ownerCandidatesUrl({}, '')).toBeNull()
  })
})
