'use client'

/**
 * The one "⋯" actions menu (web/docs/ui-style-contract.md, "Floating
 * surfaces"): one item model, two renderers. From 768 px up it is the kit's
 * anchored menu. Below it, the menu decides by fit (`action-menu-fit.ts`): a
 * short menu that fits beside its trigger stays anchored with 44 px rows; a
 * long one, one with a submenu, or one that would not fit opens as a bottom
 * sheet titled with the object's name (`action-sheet.tsx`, loaded only when a
 * phone needs it). Call sites never choose.
 *
 * Both renderers take the same items, so an item is never enabled on one and
 * disabled on the other. A click inside the menu or the sheet stays in it:
 * it never reaches a clickable row or card the trigger sits in. Permission gating stays with the caller: pass only
 * the items the user may see (hidden without permission), and give an item
 * that does not apply a `disabledReason`. A destructive item opens a
 * confirmation from its `onSelect`; it never acts directly.
 */
import * as React from 'react'
import type { LucideIcon } from 'lucide-react'

import Link from '@/components/link'
import { safeHref } from '@/lib/safe-href'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useIsMobile } from '@/hooks/use-mobile'
import { cn } from '@/lib/utils'

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

export type ActionMenuProps = {
  /** The menu's items, in order of use (most frequent first). */
  items: ActionMenuEntry[]
  /** The button that opens the menu (an icon button with an accessible name). */
  trigger: React.ReactElement
  /** Name of the object the actions apply to: the sheet title on a phone. */
  title: string
  /** What the sheet is for, read with its title on a phone, e.g. "Actions for {name}". */
  label: string
}

// The phone path (fit measuring, the small menu or the sheet) loads only on a
// phone, so the routes' shared code carries the desktop menu alone.
const PhoneActionMenu = React.lazy(() => import('./action-menu-phone'))

export function ActionMenu({ items, trigger, title, label }: ActionMenuProps) {
  const isMobile = useIsMobile()
  const menu = React.useMemo(() => normalizeActionItems(items), [items])
  if (menu.groups.length === 0) return null
  if (!isMobile) return <AnchoredActionMenu menu={menu} trigger={trigger} />
  return (
    // Until the phone code is in (a moment after the page shows), the trigger
    // shows as it is and is marked busy.
    <React.Suspense
      fallback={React.cloneElement(trigger as React.ReactElement<Record<string, unknown>>, {
        'aria-busy': true,
        'data-action-menu-pending': '',
      })}
    >
      <PhoneActionMenu menu={menu} trigger={trigger} title={title} label={label} />
    </React.Suspense>
  )
}

export type TriggerHandlers = Pick<
  React.ComponentProps<typeof DropdownMenuTrigger>,
  'ref' | 'onPointerDown' | 'onKeyDown' | 'onClick'
>

export function AnchoredActionMenu({
  menu,
  trigger,
  triggerHandlers,
  onOpenChange,
}: {
  menu: NormalizedActionMenu
  trigger: React.ReactElement
  triggerHandlers?: TriggerHandlers
  onOpenChange?: (open: boolean) => void
}) {
  return (
    <DropdownMenu onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild onClick={stopClick} {...triggerHandlers}>
        {trigger}
      </DropdownMenuTrigger>
      {/* Named by its trigger (APG menu button). */}
      <DropdownMenuContent onClick={stopClick}>
        {menu.groups.map((group, i) => (
          <React.Fragment key={group.key}>
            {i > 0 && <DropdownMenuSeparator />}
            <DropdownMenuGroup>
              {group.label && <DropdownMenuLabel>{group.label}</DropdownMenuLabel>}
              {group.items.map((entry) =>
                entry.kind === 'sub' ? (
                  <DropdownMenuSub key={entry.id}>
                    <DropdownMenuSubTrigger className={ROW}>
                      {menu.icons && entry.icon && <entry.icon aria-hidden />}
                      {entry.label}
                    </DropdownMenuSubTrigger>
                    <DropdownMenuSubContent>
                      {entry.items.map((item) => (
                        <AnchoredItem key={item.id} item={item} icons={false} />
                      ))}
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                ) : (
                  <AnchoredItem key={entry.id} item={entry} icons={menu.icons} />
                )
              )}
            </DropdownMenuGroup>
          </React.Fragment>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** 32 px rows; 44 on a phone and under a coarse pointer (touch tablets). */
const ROW = 'pointer-coarse:min-h-11 max-md:min-h-11'

function AnchoredItem({ item, icons }: { item: ActionMenuAction; icons: boolean }) {
  const icon = icons && item.icon ? <item.icon aria-hidden /> : null
  const variant = item.destructive ? 'destructive' : 'default'
  if (item.disabledReason) {
    // A disabled item gets no pointer or focus events: the reason sits on a
    // focusable wrapper (hover, keyboard) and, on a phone or under a coarse
    // pointer, as a visible line under the label (no hover on touch).
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div tabIndex={0} aria-label={`${item.label}: ${item.disabledReason}`}>
            <DropdownMenuItem disabled variant={variant} className={cn(ROW, 'items-start')}>
              {icon}
              <span className="flex min-w-0 flex-col">
                <span>{item.label}</span>
                <span className="hidden text-cap text-muted-foreground max-md:block pointer-coarse:block">
                  {item.disabledReason}
                </span>
              </span>
            </DropdownMenuItem>
          </div>
        </TooltipTrigger>
        <TooltipContent side="left">{item.disabledReason}</TooltipContent>
      </Tooltip>
    )
  }
  const content = (
    <>
      {icon}
      {item.label}
      {item.shortcut && <DropdownMenuShortcut>{item.shortcut}</DropdownMenuShortcut>}
    </>
  )
  if (item.href) {
    return (
      <DropdownMenuItem asChild variant={variant} className={ROW}>
        <Link href={safeHref(item.href) ?? '#'}>{content}</Link>
      </DropdownMenuItem>
    )
  }
  return (
    <DropdownMenuItem variant={variant} className={ROW} onSelect={item.onSelect}>
      {content}
    </DropdownMenuItem>
  )
}

/** Keeps a click in the menu from reaching a clickable row or card around the trigger. */
export function stopClick(e: React.MouseEvent) {
  e.stopPropagation()
}
