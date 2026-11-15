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

import { DropdownMenu, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import type { ActionMenuEntry } from '@/components/ui/action-menu-model'
import { useIsMobile } from '@/hooks/use-mobile'

export type {
  ActionMenuAction,
  ActionMenuEntry,
  ActionMenuGroup,
  ActionMenuSubmenu,
  NormalizedActionMenu,
} from '@/components/ui/action-menu-model'

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

// Only the trigger is in the routes' shared code: the menu's items (and on a
// phone the fit measuring and the sheet) load right after the page shows.
const ActionMenuContent = React.lazy(() => import('./action-menu-content'))
const PhoneActionMenu = React.lazy(() => import('./action-menu-phone'))

/** False when no item would show (an empty list, or only empty submenus). */
function hasItems(items: ActionMenuEntry[]): boolean {
  return items.some((e) => e.kind !== 'sub' || e.items.length > 0)
}

export function ActionMenu({ items, trigger, title, label }: ActionMenuProps) {
  const isMobile = useIsMobile()
  if (!hasItems(items)) return null
  if (!isMobile) return <AnchoredActionMenu items={items} trigger={trigger} />
  return (
    // Until the phone code is in (a moment after the page shows), the trigger
    // shows as it is and is marked busy.
    <React.Suspense
      fallback={React.cloneElement(trigger as React.ReactElement<Record<string, unknown>>, {
        'aria-busy': true,
        'data-action-menu-pending': '',
      })}
    >
      <PhoneActionMenu items={items} trigger={trigger} title={title} label={label} />
    </React.Suspense>
  )
}

export type TriggerHandlers = Pick<
  React.ComponentProps<typeof DropdownMenuTrigger>,
  'ref' | 'onPointerDown' | 'onKeyDown' | 'onClick'
>

export function AnchoredActionMenu({
  items,
  trigger,
  triggerHandlers,
  onOpenChange,
}: {
  items: ActionMenuEntry[]
  trigger: React.ReactElement
  triggerHandlers?: TriggerHandlers
  onOpenChange?: (open: boolean) => void
}) {
  return (
    <DropdownMenu onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild onClick={stopClick} {...triggerHandlers}>
        {trigger}
      </DropdownMenuTrigger>
      <React.Suspense fallback={null}>
        <ActionMenuContent items={items} />
      </React.Suspense>
    </DropdownMenu>
  )
}

/** Keeps a click on the trigger from reaching a clickable row or card around it. */
function stopClick(e: React.MouseEvent) {
  e.stopPropagation()
}
