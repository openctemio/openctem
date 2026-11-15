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
 * it never reaches a clickable row or card the trigger sits in. Permission
 * gating stays with the caller: pass only the items the user may see (hidden
 * without permission), and give an item that does not apply a
 * `disabledReason`. A destructive item opens a confirmation from its
 * `onSelect`; it never acts directly.
 *
 * Only this file is in the routes' first-load code: the menu itself
 * (`action-menu-impl.tsx`) loads right after the page shows. A press on the
 * trigger before it is in is kept, and opens the menu when it arrives.
 */
import * as React from 'react'

import type { ActionMenuEntry } from '@/components/ui/action-menu-model'

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

/** A press on the trigger that came before the menu's code: by pointer or by Enter/Space. */
export type PendingOpen = 'pointer' | 'keyboard'

const ActionMenuImpl = React.lazy(() => import('./action-menu-impl'))

/** False when no item would show (an empty list, or only empty submenus). */
function hasItems(items: ActionMenuEntry[]): boolean {
  return items.some((e) => e.kind !== 'sub' || e.items.length > 0)
}

/**
 * The trigger as it shows while the menu's code loads: marked busy, and a
 * press on it is kept (`onPress`) instead of lost.
 */
export function pendingTrigger(
  trigger: React.ReactElement,
  onPress: (how: PendingOpen) => void
): React.ReactElement {
  return React.cloneElement(trigger as React.ReactElement<Record<string, unknown>>, {
    'aria-busy': true,
    'data-action-menu-pending': '',
    onClick: (e: React.MouseEvent) => {
      e.stopPropagation()
      // A click with no pointer position came from Enter or Space.
      onPress(e.detail === 0 ? 'keyboard' : 'pointer')
    },
  })
}

export function ActionMenu(props: ActionMenuProps) {
  const [pending, setPending] = React.useState<PendingOpen | undefined>(undefined)
  if (!hasItems(props.items)) return null
  return (
    <React.Suspense fallback={pendingTrigger(props.trigger, setPending)}>
      <ActionMenuImpl {...props} pendingOpen={pending} />
    </React.Suspense>
  )
}
