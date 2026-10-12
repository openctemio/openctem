/**
 * StatusSelect only offers "Resolved" to people who hold findings:verify: the
 * API refuses a resolve from anyone else, so a member marks "Fix applied" and a
 * retest, a verified scan or a security reviewer closes the finding.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StatusSelect } from '../status-select'

let mockPerms: string[] = []

// Radix menus measure their trigger; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockPerms.includes(p) }),
}))

async function openMenu() {
  render(<StatusSelect value="fix_applied" onChange={vi.fn()} />)
  await userEvent.click(screen.getByRole('button'))
}

describe('StatusSelect resolve gate', () => {
  it('hides Resolved without findings:verify', async () => {
    mockPerms = ['findings:status', 'findings:fix_apply']
    await openMenu()
    expect(screen.queryByRole('menuitem', { name: /resolved/i })).toBeNull()
    expect(screen.getByRole('menuitem', { name: /in progress/i })).toBeTruthy()
  })

  it('offers Resolved with findings:verify', async () => {
    mockPerms = ['findings:status', 'findings:verify']
    await openMenu()
    expect(screen.getByRole('menuitem', { name: /resolved/i })).toBeTruthy()
  })
})
