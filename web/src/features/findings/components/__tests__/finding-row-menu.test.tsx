import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { FindingRowMenu, type FindingRowAction } from '../finding-row-menu'
import { ROW_MENU_REASON_FALLBACK, type RowMenuFinding } from '../../lib/row-menu-state'

Element.prototype.scrollIntoView ??= () => {}
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

type Can = {
  canAssign?: boolean
  canChangeStatus?: boolean
  canCreateTicket?: boolean
  canRemediate?: boolean
  canDelete?: boolean
}

const OPEN: RowMenuFinding = { status: 'confirmed', source: 'sast' }

async function openMenu(
  can: Can = {},
  finding: RowMenuFinding = OPEN,
  onAction: (action: FindingRowAction) => void = vi.fn()
) {
  render(
    <FindingRowMenu
      title="SQL injection"
      finding={finding}
      onAction={onAction}
      canAssign={can.canAssign ?? true}
      canChangeStatus={can.canChangeStatus ?? true}
      canCreateTicket={can.canCreateTicket ?? true}
      canRemediate={can.canRemediate ?? true}
      canDelete={can.canDelete ?? true}
    />
  )
  await userEvent.click(screen.getByRole('button', { name: /Actions for SQL injection/ }))
  await screen.findByRole('menuitem', { name: 'View details' })
}

const labels = () => screen.getAllByRole('menuitem').map((el) => el.textContent?.trim())
const item = (name: string) => screen.getByRole('menuitem', { name })
const disabledItems = () =>
  screen.getAllByRole('menuitem').filter((el) => el.getAttribute('aria-disabled') === 'true')

describe('FindingRowMenu', () => {
  it('lists every action in one fixed order', async () => {
    await openMenu()
    expect(labels()).toEqual([
      'View details',
      'Open to assign…',
      'Open to change status…',
      'Create ticket',
      'Add to remediation',
      'Copy ID',
      'Copy link',
      'Open to mark as false positive…',
      'Delete',
    ])
  })

  it('hides each change the user has no permission for and keeps the order of the rest', async () => {
    await openMenu({
      canAssign: false,
      canChangeStatus: false,
      canCreateTicket: false,
      canRemediate: false,
      canDelete: false,
    })
    expect(labels()).toEqual(['View details', 'Copy ID', 'Copy link'])
  })

  it.each<[keyof Can, string[]]>([
    ['canAssign', ['Open to assign…']],
    ['canChangeStatus', ['Open to change status…', 'Open to mark as false positive…']],
    ['canCreateTicket', ['Create ticket']],
    ['canRemediate', ['Add to remediation']],
    ['canDelete', ['Delete']],
  ])('without %s the menu has no %j', async (flag, hidden) => {
    await openMenu({ [flag]: false })
    for (const name of hidden) expect(screen.queryByRole('menuitem', { name })).toBeNull()
  })

  it('disables nothing for an open scanner finding without a ticket', async () => {
    await openMenu()
    expect(disabledItems()).toEqual([])
  })

  it('disables Create ticket, with the reason, when a ticket is already linked', async () => {
    const onAction = vi.fn()
    await openMenu({}, { ...OPEN, workItemUris: ['https://tickets.example.com/SEC-1'] }, onAction)
    const row = screen.getByRole('menuitem', { name: /Create ticket/ })
    expect(row).toHaveAttribute('aria-disabled', 'true')
    expect(row).toHaveTextContent(ROW_MENU_REASON_FALLBACK.ticketLinked)
    expect(
      screen.getByLabelText(`Create ticket: ${ROW_MENU_REASON_FALLBACK.ticketLinked}`)
    ).toBeInTheDocument()
    await userEvent.click(row, { pointerEventsCheck: 0 })
    expect(onAction).not.toHaveBeenCalled()
    expect(disabledItems()).toHaveLength(1)
  })

  it.each<[string, RowMenuFinding, string]>([
    [
      'already a false positive',
      { status: 'false_positive', source: 'sast' },
      'alreadyFalsePositive',
    ],
    ['resolved', { status: 'resolved', source: 'sast' }, 'closed'],
    ['risk accepted', { status: 'accepted', source: 'sast' }, 'closed'],
  ])('disables mark as false positive on a finding that is %s', async (_n, finding, code) => {
    await openMenu({}, finding)
    const reason = ROW_MENU_REASON_FALLBACK[code as keyof typeof ROW_MENU_REASON_FALLBACK]
    const row = screen.getByRole('menuitem', { name: /Open to mark as false positive…/ })
    expect(row).toHaveAttribute('aria-disabled', 'true')
    expect(row).toHaveTextContent(reason)
    // It can still be reopened: the status item stays.
    expect(item('Open to change status…')).not.toHaveAttribute('aria-disabled', 'true')
    expect(disabledItems()).toHaveLength(1)
  })

  it('disables assign, status and false positive on a finding people reported', async () => {
    await openMenu({}, { status: 'confirmed', source: 'pentest' })
    const reason = ROW_MENU_REASON_FALLBACK.managedElsewhere
    for (const name of [
      /Open to assign…/,
      /Open to change status…/,
      /Open to mark as false positive…/,
    ]) {
      const row = screen.getByRole('menuitem', { name })
      expect(row).toHaveAttribute('aria-disabled', 'true')
      expect(row).toHaveTextContent(reason)
    }
    expect(disabledItems()).toHaveLength(3)
  })

  it('never disables an item without saying why', async () => {
    await openMenu(
      {},
      {
        status: 'resolved',
        source: 'bug_bounty',
        workItemUris: ['https://tickets.example.com/SEC-2'],
      }
    )
    const off = disabledItems()
    expect(off.length).toBeGreaterThan(0)
    const reasons = Object.values(ROW_MENU_REASON_FALLBACK)
    for (const el of off) expect(reasons.some((r) => el.textContent?.includes(r))).toBe(true)
  })
})
