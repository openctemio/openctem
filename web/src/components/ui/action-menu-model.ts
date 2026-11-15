/**
 * The item model of `ActionMenu` and the content rules every action menu
 * follows (web/docs/ui-style-contract.md, "Floating surfaces").
 */
import type { LucideIcon } from 'lucide-react'

type ActionBase = {
  id: string
  label: string
  icon?: LucideIcon
  /** Heading of the group the item belongs to; items without one share a group. */
  group?: string
  /** A group without a heading (a divider only), for items set apart from their neighbours. */
  section?: string
}

export type ActionMenuAction = ActionBase & {
  kind?: 'item'
  onSelect?: () => void
  /** Navigates instead (an internal path). */
  href?: string
  /** The item does not apply here: shown dimmed with this reason. */
  disabledReason?: string
  /** Deletes or revokes: red, in the last group; its onSelect opens the confirmation. */
  destructive?: boolean
  /** Keyboard shortcut hint (desktop with a fine pointer only). */
  shortcut?: string
}

export type ActionMenuSubmenu = ActionBase & {
  kind: 'sub'
  items: ActionMenuAction[]
}

export type ActionMenuEntry = ActionMenuAction | ActionMenuSubmenu

export type ActionMenuGroup<T = ActionMenuEntry> = {
  key: string
  /** Shown only when the menu has two groups or more and this one has two items or more. */
  label?: string
  items: T[]
}

export type NormalizedActionMenu = {
  groups: ActionMenuGroup[]
  /** Icons are shown for every item or for none. */
  icons: boolean
}

const DESTRUCTIVE_GROUP = '\u0000destructive'

/** Group key of an entry: a heading (`group`), an unnamed `section`, or the default group. */
function groupKey(entry: ActionMenuEntry): string {
  if (entry.group) return `g:${entry.group}`
  if (entry.section) return `s:${entry.section}`
  return ''
}

function isDestructive(entry: ActionMenuEntry): boolean {
  return entry.kind !== 'sub' && !!entry.destructive
}

/**
 * The content rules every action menu follows, whatever the call site passes:
 * groups in first-seen order, destructive items last in a group of their own,
 * empty submenus dropped, a group heading only for a group of two items or
 * more in a menu of two groups or more, icons for all items or none.
 */
export function normalizeActionItems(entries: ActionMenuEntry[]): NormalizedActionMenu {
  const order: string[] = []
  const byKey = new Map<string, ActionMenuEntry[]>()
  const add = (key: string, entry: ActionMenuEntry) => {
    if (!byKey.has(key)) {
      byKey.set(key, [])
      order.push(key)
    }
    byKey.get(key)!.push(entry)
  }
  for (const entry of entries) {
    if (entry.kind === 'sub') {
      const items = entry.items.filter(Boolean)
      if (items.length === 0) continue
      add(groupKey(entry), { ...entry, items })
    } else {
      add(isDestructive(entry) ? DESTRUCTIVE_GROUP : groupKey(entry), entry)
    }
  }
  const keys = order.filter((k) => k !== DESTRUCTIVE_GROUP)
  if (byKey.has(DESTRUCTIVE_GROUP)) keys.push(DESTRUCTIVE_GROUP)
  const many = keys.length >= 2
  const groups = keys.map((key) => {
    const items = byKey.get(key)!
    const heading = key.startsWith('g:') ? key.slice(2) : undefined
    return { key, label: heading && many && items.length >= 2 ? heading : undefined, items }
  })
  const all = groups.flatMap((g) => g.items)
  return { groups, icons: all.length > 0 && all.every((e) => !!e.icon) }
}
