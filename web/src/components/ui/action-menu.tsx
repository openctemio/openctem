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
 * A menu of one item is not a menu (owner rule: an overflow menu never holds
 * a single item): with exactly one action left (after permission and width
 * folding) that has an icon, the trigger itself becomes that action, in the
 * trigger's place and size, named and titled by it. Pages merge a lone item
 * into their other menu instead; outside production a console error names
 * any one-item menu so a page does not ship one by accident. A lone
 * destructive action (Delete, Remove, Revoke) is the exception: it stays
 * behind the "..." trigger, without the error, so a row never shows a bare
 * destructive button; a row's other direct action joins that menu instead.
 *
 * Only this file is in the routes' first-load code: the menu itself
 * (`action-menu-impl.tsx`) loads right after the page shows. A press on the
 * trigger before it is in is kept, and opens the menu when it arrives.
 */
import * as React from 'react'
import { useRouter } from 'next/navigation'

import type { ActionMenuAction, ActionMenuEntry } from '@/components/ui/action-menu-model'
import { safeHref } from '@/lib/safe-href'

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

type ImplModule = typeof import('./action-menu-impl')

let loaded: ImplModule | undefined

/** Loads the menu's code (also the way to have it in before the first render). */
export function preloadActionMenu(): Promise<ImplModule> {
  return import('./action-menu-impl').then((m) => (loaded = m))
}

// Once the code is in, a menu that mounts later renders at once: React reads a
// thenable that calls back synchronously without suspending. So only the first
// menu on a page shows its trigger busy, and the button is never swapped
// under a press that is still in flight.
const ActionMenuImpl = React.lazy(
  () =>
    (loaded
      ? { then: (resolve: (m: ImplModule) => void) => resolve(loaded as ImplModule) }
      : preloadActionMenu()) as Promise<ImplModule>
)

/** False when no item would show (an empty list, or only empty submenus). */
function hasItems(items: ActionMenuEntry[]): boolean {
  return items.some((e) => e.kind !== 'sub' || e.items.length > 0)
}

/**
 * The one action of a menu that would hold a single item, else null. A lone
 * destructive action is never one: it stays behind the "..." trigger, the one
 * menu that may hold a single item, so a row never shows a bare Delete.
 */
export function soleAction(items: ActionMenuEntry[]): ActionMenuAction | null {
  const shown = items.flatMap((e) => (e.kind === 'sub' ? e.items : [e]))
  return shown.length === 1 && !shown[0].destructive ? shown[0] : null
}

/** The trigger turned into the one action: same place, size and look. */
function SoleActionButton({
  item,
  trigger,
}: {
  item: ActionMenuAction
  trigger: React.ReactElement
}) {
  const router = useRouter()
  const Icon = item.icon
  return React.cloneElement(trigger as React.ReactElement<Record<string, unknown>>, {
    'aria-label': item.label,
    title: item.disabledReason ?? item.label,
    'aria-haspopup': undefined,
    'data-sole-action': '',
    disabled: !!item.disabledReason,
    children: Icon ? <Icon aria-hidden="true" /> : item.label,
    onClick: (e: React.MouseEvent) => {
      e.stopPropagation()
      if (item.disabledReason) return
      if (item.href) router.push(safeHref(item.href) ?? '/')
      else item.onSelect?.()
    },
  })
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
  const sole = soleAction(props.items)
  const soleLabel = sole?.label
  React.useEffect(() => {
    if (soleLabel !== undefined && process.env.NODE_ENV !== 'production')
      console.error(
        `ActionMenu: "${soleLabel}" is the only item; an overflow menu never holds one item. Put it in the page's other menu or show it as a button.`
      )
  }, [soleLabel])
  if (!hasItems(props.items)) return null
  // With its icon the one action takes the trigger's square in its place.
  // Without one it cannot (a label does not fit an icon button): the menu
  // stays, and the console error above asks the page to place it.
  if (sole?.icon) return <SoleActionButton item={sole} trigger={props.trigger} />
  return (
    <React.Suspense fallback={pendingTrigger(props.trigger, setPending)}>
      <ActionMenuImpl {...props} pendingOpen={pending} />
    </React.Suspense>
  )
}
