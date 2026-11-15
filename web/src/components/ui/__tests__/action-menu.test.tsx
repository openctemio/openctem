/**
 * ActionMenu: one item model, an anchored menu from 768 px up and a bottom
 * sheet below (web/docs/ui-style-contract.md, "Floating surfaces"). The
 * content rules are enforced by normalizeActionItems, not by review.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ClipboardList, FileUp, Trash2 } from 'lucide-react'
import * as React from 'react'

import { ActionMenu, normalizeActionItems, type ActionMenuEntry } from '../action-menu'

describe('normalizeActionItems', () => {
  it('keeps groups in first-seen order and moves destructive items last, on their own', () => {
    const menu = normalizeActionItems([
      { id: 'delete', label: 'Delete', destructive: true },
      { id: 'edit', label: 'Edit', group: 'Change' },
      { id: 'copy', label: 'Copy ID' },
      { id: 'rename', label: 'Rename', group: 'Change' },
    ])
    expect(menu.groups.map((g) => g.items.map((i) => i.id))).toEqual([
      ['edit', 'rename'],
      ['copy'],
      ['delete'],
    ])
  })

  it('shows a group heading only for two items or more in a menu of two groups or more', () => {
    const one = normalizeActionItems([
      { id: 'import', label: 'Import results', group: 'Create' },
      { id: 'approvals', label: 'Approvals' },
    ])
    expect(one.groups.map((g) => g.label)).toEqual([undefined, undefined])

    const two = normalizeActionItems([
      { id: 'csv', label: 'CSV', group: 'Export' },
      { id: 'json', label: 'JSON', group: 'Export' },
      { id: 'approvals', label: 'Approvals' },
    ])
    expect(two.groups.map((g) => g.label)).toEqual(['Export', undefined])

    const alone = normalizeActionItems([
      { id: 'csv', label: 'CSV', group: 'Export' },
      { id: 'json', label: 'JSON', group: 'Export' },
    ])
    expect(alone.groups[0].label).toBeUndefined()
  })

  it('shows icons for every item or for none', () => {
    expect(
      normalizeActionItems([
        { id: 'a', label: 'A', icon: FileUp },
        { id: 'b', label: 'B', icon: ClipboardList },
      ]).icons
    ).toBe(true)
    expect(
      normalizeActionItems([
        { id: 'a', label: 'A', icon: FileUp },
        { id: 'b', label: 'B' },
      ]).icons
    ).toBe(false)
  })

  it('splits a section off with a divider and never heads it', () => {
    const menu = normalizeActionItems([
      { id: 'view', label: 'View' },
      { id: 'copy', label: 'Copy ID', section: 'copy' },
      { id: 'link', label: 'Copy link', section: 'copy' },
      { id: 'csv', label: 'CSV', group: 'Export' },
      { id: 'json', label: 'JSON', group: 'Export' },
    ])
    expect(menu.groups.map((g) => g.items.map((i) => i.id))).toEqual([
      ['view'],
      ['copy', 'link'],
      ['csv', 'json'],
    ])
    expect(menu.groups.map((g) => g.label)).toEqual([undefined, undefined, 'Export'])
  })

  it('drops an empty submenu and has no groups for no items', () => {
    expect(
      normalizeActionItems([{ id: 's', kind: 'sub', label: 'Move to', items: [] }]).groups
    ).toEqual([])
    expect(normalizeActionItems([]).groups).toEqual([])
  })
})

const desktopWidth = window.innerWidth

function setWidth(w: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: w })
}

/** On a phone the menu code loads lazily: wait until the trigger is the real one. */
async function phoneReady() {
  await waitFor(() => expect(document.querySelector('[data-action-menu-pending]')).toBeNull())
}

function Harness({ items, onImport }: { items?: ActionMenuEntry[]; onImport?: () => void }) {
  return (
    <ActionMenu
      title="Findings"
      label="Actions for Findings"
      trigger={<button aria-label="More actions">More</button>}
      items={
        items ?? [
          {
            id: 'import',
            group: 'Create',
            label: 'Import results',
            icon: FileUp,
            onSelect: onImport,
          },
          { id: 'approvals', label: 'Approvals', icon: ClipboardList, href: '/findings/approvals' },
          {
            id: 'delete',
            label: 'Delete view',
            icon: Trash2,
            destructive: true,
            disabledReason: 'Built-in views cannot be deleted',
          },
          {
            id: 'move',
            kind: 'sub',
            label: 'Move to',
            items: [
              { id: 'p1', label: 'Project one' },
              { id: 'p2', label: 'Project two' },
            ],
          },
        ]
      }
    />
  )
}

describe('ActionMenu from 768 px up', () => {
  beforeEach(() => setWidth(1024))
  afterEach(() => setWidth(desktopWidth))

  it('is an anchored menu (APG menu button) with no heading over a single item', async () => {
    render(<Harness />)
    const trigger = screen.getByRole('button', { name: 'More actions' })
    expect(trigger).toHaveAttribute('aria-haspopup', 'menu')
    await userEvent.click(trigger)
    const menu = await screen.findByRole('menu', { name: 'More actions' })
    expect(within(menu).getByRole('menuitem', { name: 'Import results' })).toBeVisible()
    expect(within(menu).queryByText('Create')).toBeNull()
    // Destructive last: after every other item.
    const items = within(menu).getAllByRole('menuitem')
    expect(items.at(-1)).toHaveTextContent('Delete view')
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(trigger).toHaveFocus()
  })

  it('keeps clicks on the trigger and in the menu from reaching a clickable row', async () => {
    const onRow = vi.fn()
    const onImport = vi.fn()
    render(
      <div onClick={onRow}>
        <Harness onImport={onImport} />
      </div>
    )
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    const menu = await screen.findByRole('menu')
    await userEvent.click(within(menu).getByRole('menuitem', { name: 'Import results' }))
    expect(onImport).toHaveBeenCalledOnce()
    expect(onRow).not.toHaveBeenCalled()
  })

  it('renders nothing when no item is left', () => {
    const { container } = render(<Harness items={[]} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('ActionMenu below 768 px', () => {
  beforeEach(() => setWidth(390))
  afterEach(() => setWidth(desktopWidth))

  async function openSheet(onImport?: () => void) {
    render(<Harness onImport={onImport} />)
    await phoneReady()
    const trigger = screen.getByRole('button', { name: 'More actions' })
    expect(trigger).toHaveAttribute('aria-haspopup', 'dialog')
    await userEvent.click(trigger)
    const sheet = await screen.findByRole('dialog', { name: 'Findings' })
    return { trigger, sheet }
  }

  it('is a bottom sheet titled with the object, a close button and no icons', async () => {
    const { sheet, trigger } = await openSheet()
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(sheet).toHaveAttribute('data-vaul-drawer-direction', 'bottom')
    expect(within(sheet).getByRole('button', { name: 'Close' })).toBeVisible()
    expect(
      sheet.querySelectorAll('[data-slot="action-sheet-row"] svg.lucide-file-up')
    ).toHaveLength(0)
    const rows = [...sheet.querySelectorAll('[data-slot="action-sheet-row"]')].map(
      (r) => r.textContent
    )
    // Destructive group last.
    expect(rows.at(-1)).toContain('Delete view')
  })

  it('shows the reason of an unavailable item as text and does not act on it', async () => {
    const { sheet } = await openSheet()
    const row = within(sheet).getByRole('button', { name: /Delete view/ })
    expect(row).toHaveAttribute('aria-disabled', 'true')
    expect(within(sheet).getByText('Built-in views cannot be deleted')).toBeVisible()
    expect(row).toHaveAccessibleDescription('Built-in views cannot be deleted')
    await userEvent.click(row)
    expect(screen.getByRole('dialog', { name: 'Findings' })).toBeInTheDocument()
  })

  it('runs an action and closes, returning focus to the trigger', async () => {
    const onImport = vi.fn()
    const { sheet, trigger } = await openSheet(onImport)
    await userEvent.click(within(sheet).getByRole('button', { name: 'Import results' }))
    expect(onImport).toHaveBeenCalledOnce()
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it('keeps clicks on the trigger and in the sheet from reaching a clickable card', async () => {
    const onCard = vi.fn()
    const onImport = vi.fn()
    render(
      <div onClick={onCard}>
        <Harness onImport={onImport} />
      </div>
    )
    await phoneReady()
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    const sheet = await screen.findByRole('dialog', { name: 'Findings' })
    await userEvent.click(within(sheet).getByRole('button', { name: 'Import results' }))
    expect(onImport).toHaveBeenCalledOnce()
    expect(onCard).not.toHaveBeenCalled()
  })

  it('drills into a submenu with a Back row; Escape goes back one level, then closes', async () => {
    const { sheet } = await openSheet()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Move to' }))
    expect(await screen.findByRole('dialog', { name: 'Move to' })).toBeInTheDocument()
    expect(within(sheet).getByRole('button', { name: 'Back' })).toBeVisible()
    expect(within(sheet).getByRole('button', { name: 'Project one' })).toBeVisible()
    await userEvent.keyboard('{Escape}')
    expect(await screen.findByRole('dialog', { name: 'Findings' })).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('focuses the first row only when opened from the keyboard', async () => {
    render(<Harness />)
    await phoneReady()
    const trigger = screen.getByRole('button', { name: 'More actions' })
    trigger.focus()
    await userEvent.keyboard('{Enter}')
    const sheet = await screen.findByRole('dialog', { name: 'Findings' })
    await waitFor(() =>
      expect(within(sheet).getByRole('button', { name: 'Import results' })).toHaveFocus()
    )
  })
})

describe('ActionMenu below 768 px, by fit', () => {
  const desktopHeight = window.innerHeight
  beforeEach(() => setWidth(390))
  afterEach(() => {
    setWidth(desktopWidth)
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: desktopHeight })
  })

  const short: ActionMenuEntry[] = [
    { id: 'import', label: 'Import results', icon: FileUp },
    {
      id: 'approvals',
      label: 'Approvals',
      icon: ClipboardList,
      disabledReason: 'Needs the approver role',
    },
  ]

  it('a short menu that fits is an anchored menu with visible reasons', async () => {
    render(<Harness items={short} />)
    await phoneReady()
    const trigger = screen.getByRole('button', { name: 'More actions' })
    expect(trigger).toHaveAttribute('aria-haspopup', 'menu')
    await userEvent.click(trigger)
    const menu = await screen.findByRole('menu', { name: 'More actions' })
    expect(within(menu).getByRole('menuitem', { name: 'Import results' })).toBeVisible()
    expect(within(menu).getByText('Needs the approver role')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(trigger).toHaveFocus()
  })

  it('seven items open the sheet', async () => {
    const many: ActionMenuEntry[] = Array.from({ length: 7 }, (_, i) => ({
      id: `a${i}`,
      label: `Action ${i}`,
    }))
    render(<Harness items={many} />)
    await phoneReady()
    const trigger = screen.getByRole('button', { name: 'More actions' })
    expect(trigger).toHaveAttribute('aria-haspopup', 'dialog')
    await userEvent.click(trigger)
    expect(await screen.findByRole('dialog', { name: 'Findings' })).toBeInTheDocument()
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('a short menu without room beside its trigger opens the sheet', async () => {
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 90 })
    render(<Harness items={short} />)
    await phoneReady()
    const trigger = screen.getByRole('button', { name: 'More actions' })
    await userEvent.click(trigger)
    expect(await screen.findByRole('dialog', { name: 'Findings' })).toBeInTheDocument()
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('from the keyboard, a menu without room opens the sheet on its first row', async () => {
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 90 })
    render(<Harness items={short} />)
    await phoneReady()
    screen.getByRole('button', { name: 'More actions' }).focus()
    await userEvent.keyboard('{Enter}')
    const sheet = await screen.findByRole('dialog', { name: 'Findings' })
    await waitFor(() =>
      expect(within(sheet).getByRole('button', { name: 'Import results' })).toHaveFocus()
    )
  })
})
