import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { FindingRowMenu } from '../finding-row-menu'

Element.prototype.scrollIntoView ??= () => {}
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

async function openMenu(over: { canAssign?: boolean; canChangeStatus?: boolean } = {}) {
  render(
    <FindingRowMenu
      title="SQL injection"
      onAction={vi.fn()}
      canAssign={over.canAssign ?? true}
      canChangeStatus={over.canChangeStatus ?? true}
      canCreateTicket={false}
      canRemediate={false}
      canDelete={false}
    />
  )
  await userEvent.click(screen.getByRole('button', { name: /Actions for SQL injection/ }))
  await screen.findByRole('menuitem', { name: 'View details' })
}

describe('FindingRowMenu', () => {
  it('offers assign, status and false positive to someone who may make those changes', async () => {
    await openMenu()
    expect(screen.getByRole('menuitem', { name: 'Open to assign…' })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Open to change status…' })).toBeInTheDocument()
    expect(
      screen.getByRole('menuitem', { name: 'Open to mark as false positive…' })
    ).toBeInTheDocument()
  })

  it('offers no change the API would refuse', async () => {
    await openMenu({ canAssign: false, canChangeStatus: false })
    expect(screen.queryByRole('menuitem', { name: 'Open to assign…' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Open to change status…' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Open to mark as false positive…' })).toBeNull()
    // Reading actions stay.
    expect(screen.getByRole('menuitem', { name: 'Copy link' })).toBeInTheDocument()
  })
})
