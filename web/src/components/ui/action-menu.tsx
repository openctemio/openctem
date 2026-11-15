'use client'

/**
 * The one "⋯" actions menu (web/docs/ui-style-contract.md, "Floating
 * surfaces"): one item model, two renderers. From 768 px up it is the kit's
 * anchored menu; below it opens as a bottom sheet titled with the object's
 * name (`action-sheet.tsx`, loaded only when a phone opens it, so desktop
 * routes never download it).
 *
 * Both renderers take the same items, so an item is never enabled on one and
 * disabled on the other. Permission gating stays with the caller: pass only
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
      add(entry.group ?? '', { ...entry, items })
    } else {
      add(isDestructive(entry) ? DESTRUCTIVE_GROUP : (entry.group ?? ''), entry)
    }
  }
  const keys = order.filter((k) => k !== DESTRUCTIVE_GROUP)
  if (byKey.has(DESTRUCTIVE_GROUP)) keys.push(DESTRUCTIVE_GROUP)
  const many = keys.length >= 2
  const groups = keys.map((key) => {
    const items = byKey.get(key)!
    const named = key !== '' && key !== DESTRUCTIVE_GROUP
    return { key, label: named && many && items.length >= 2 ? key : undefined, items }
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

const ActionSheet = React.lazy(() => import('./action-sheet'))

/** Starts loading the sheet as soon as a finger lands on the trigger. */
function preloadSheet() {
  void import('./action-sheet')
}

export function ActionMenu({ items, trigger, title, label }: ActionMenuProps) {
  const isMobile = useIsMobile()
  const menu = React.useMemo(() => normalizeActionItems(items), [items])
  if (menu.groups.length === 0) return null
  return isMobile ? (
    <PhoneActionMenu menu={menu} trigger={trigger} title={title} label={label} />
  ) : (
    <AnchoredActionMenu menu={menu} trigger={trigger} />
  )
}

function AnchoredActionMenu({
  menu,
  trigger,
}: {
  menu: NormalizedActionMenu
  trigger: React.ReactElement
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
      {/* Named by its trigger (APG menu button). */}
      <DropdownMenuContent>
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

/** 32 px rows; 44 under a coarse pointer (touch tablets). */
const ROW = 'pointer-coarse:min-h-11'

function AnchoredItem({ item, icons }: { item: ActionMenuAction; icons: boolean }) {
  const icon = icons && item.icon ? <item.icon aria-hidden /> : null
  const variant = item.destructive ? 'destructive' : 'default'
  if (item.disabledReason) {
    // A disabled item gets no pointer or focus events: the reason sits on a
    // focusable wrapper (hover, keyboard) and, under a coarse pointer, as a
    // visible line under the label (no hover on touch).
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div tabIndex={0} aria-label={`${item.label}: ${item.disabledReason}`}>
            <DropdownMenuItem disabled variant={variant} className={cn(ROW, 'items-start')}>
              {icon}
              <span className="flex min-w-0 flex-col">
                <span>{item.label}</span>
                <span className="hidden text-cap text-muted-foreground pointer-coarse:block">
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

function PhoneActionMenu({
  menu,
  trigger,
  title,
  label,
}: {
  menu: NormalizedActionMenu
  trigger: React.ReactElement
  title: string
  label: string
}) {
  const [open, setOpen] = React.useState(false)
  // Mounted after the first open and kept, so the sheet can animate closed.
  const [mounted, setMounted] = React.useState(false)
  const [byKeyboard, setByKeyboard] = React.useState(false)
  const triggerRef = React.useRef<HTMLElement | null>(null)
  // On a phone, fetch the sheet while the page is idle, so the first tap
  // opens it at once (desktop never loads it).
  React.useEffect(() => {
    if (typeof window.requestIdleCallback !== 'function') return
    const id = window.requestIdleCallback(preloadSheet, { timeout: 4000 })
    return () => window.cancelIdleCallback(id)
  }, [])

  const triggerProps = trigger.props as {
    onClick?: (e: React.MouseEvent<HTMLElement>) => void
    onPointerDown?: (e: React.PointerEvent<HTMLElement>) => void
  }
  const opener = React.cloneElement(trigger as React.ReactElement<Record<string, unknown>>, {
    ref: triggerRef,
    'aria-haspopup': 'dialog',
    'aria-expanded': open,
    onPointerDown: (e: React.PointerEvent<HTMLElement>) => {
      triggerProps.onPointerDown?.(e)
      preloadSheet()
    },
    onClick: (e: React.MouseEvent<HTMLElement>) => {
      triggerProps.onClick?.(e)
      if (e.defaultPrevented) return
      // A click with no pointer position came from Enter or Space.
      setByKeyboard(e.detail === 0)
      setMounted(true)
      setOpen(true)
    },
  })

  return (
    <>
      {opener}
      {mounted && (
        <React.Suspense fallback={null}>
          <ActionSheet
            open={open}
            onOpenChange={setOpen}
            menu={menu}
            title={title}
            label={label}
            focusFirstRow={byKeyboard}
            returnFocusTo={triggerRef}
          />
        </React.Suspense>
      )}
    </>
  )
}
