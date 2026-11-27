/**
 * DataTableRowActions renders the shared ActionMenu: gated items hidden from
 * someone who may not use them, unavailable items disabled with a reason,
 * dividers from `separatorBefore`, destructive items last.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Trash2 } from 'lucide-react'

const perms = vi.hoisted(() => ({ list: [] as string[], loading: false, role: 'member' }))

vi.mock('@/lib/permissions', async (orig) => {
  const real = await orig<typeof import('@/lib/permissions')>()
  return {
    ...real,
    usePermissions: () => ({
      permissions: perms.list,
      can: (p: string) => perms.list.includes(p),
      isLoading: perms.loading,
      tenantRole: perms.role,
    }),
  }
})

import { DataTableRowActions } from '../data-table-row-actions'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  perms.list = []
  perms.loading = false
  perms.role = 'member'
})

async function open(name = 'Open row actions') {
  await userEvent.click(screen.getByRole('button', { name }))
  return screen.findByRole('menu')
}

describe('DataTableRowActions', () => {
  it('hides an item gated by a permission the user lacks and shows it to one who has it', async () => {
    const actions = [
      { label: 'View', onClick: vi.fn() },
      { label: 'Edit', onClick: vi.fn(), permission: 'assets:write' },
    ]
    const { unmount } = render(<DataTableRowActions actions={actions} />)
    let menu = await open()
    expect(within(menu).queryByRole('menuitem', { name: 'Edit' })).toBeNull()
    unmount()

    perms.list = ['assets:write']
    render(<DataTableRowActions actions={actions} />)
    menu = await open()
    expect(within(menu).getByRole('menuitem', { name: 'Edit' })).toBeInTheDocument()
  })

  it('hides gated items while permissions load, except for owners and admins', async () => {
    perms.list = ['assets:write']
    perms.loading = true
    const actions = [
      { label: 'View', onClick: vi.fn() },
      { label: 'Edit', onClick: vi.fn(), permission: 'assets:write' },
    ]
    const { unmount } = render(<DataTableRowActions actions={actions} />)
    expect(within(await open()).queryByRole('menuitem', { name: 'Edit' })).toBeNull()
    unmount()
    perms.role = 'admin'
    render(<DataTableRowActions actions={actions} />)
    expect(within(await open()).getByRole('menuitem', { name: 'Edit' })).toBeInTheDocument()
  })

  it('gives an unavailable item without a reason a general one, and does not run it', async () => {
    const onClick = vi.fn()
    render(<DataTableRowActions actions={[{ label: 'Sync', onClick, disabled: true }]} />)
    const menu = await open()
    const item = within(menu).getByRole('menuitem', { name: /^Sync/ })
    expect(item).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByLabelText('Sync: Not available right now')).toBeInTheDocument()
    await userEvent.click(item)
    expect(onClick).not.toHaveBeenCalled()
  })

  it('puts a divider at separatorBefore and the destructive item last', async () => {
    render(
      <DataTableRowActions
        label="Actions for web-01"
        actions={[
          { label: 'Delete', onClick: vi.fn(), destructive: true, icon: Trash2 },
          { label: 'View', onClick: vi.fn() },
          { label: 'Copy ID', onClick: vi.fn(), separatorBefore: true },
        ]}
      />
    )
    const menu = await open('Actions for web-01')
    expect(
      within(menu)
        .getAllByRole('menuitem')
        .map((i) => i.textContent)
    ).toEqual(['View', 'Copy ID', 'Delete'])
    expect(within(menu).getAllByRole('separator')).toHaveLength(2)
  })

  it('runs the chosen action and the click does not reach the row', async () => {
    const onClick = vi.fn()
    const onRow = vi.fn()
    render(
      <div onClick={onRow}>
        <DataTableRowActions actions={[{ label: 'View', onClick }]} />
      </div>
    )
    const menu = await open()
    await userEvent.click(within(menu).getByRole('menuitem', { name: 'View' }))
    expect(onClick).toHaveBeenCalledOnce()
    expect(onRow).not.toHaveBeenCalled()
  })
})
