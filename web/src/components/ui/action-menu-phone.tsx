'use client'

/**
 * The phone path of `ActionMenu` (loaded only on a phone): it chooses the
 * presentation by fit (`action-menu-fit.ts`) each time the menu opens, the
 * kit's anchored menu with 44 px rows when the menu is short and fits beside
 * its trigger, the bottom sheet (`action-sheet.tsx`) otherwise.
 */
import * as React from 'react'

import type { PendingOpen } from '@/components/ui/action-menu'
import { AnchoredActionMenu, type TriggerHandlers } from '@/components/ui/action-menu-impl'
import {
  normalizeActionItems,
  type ActionMenuEntry,
  type NormalizedActionMenu,
} from '@/components/ui/action-menu-model'
import {
  mayBeAnchoredOnPhone,
  measurePhoneFit,
  type PhoneMenuModel,
} from '@/components/ui/action-menu-fit'

const ActionSheet = React.lazy(() => import('./action-sheet'))

/** Starts loading the sheet as soon as a finger lands on the trigger. */
function preloadSheet() {
  void import('./action-sheet')
}

/** What the phone fit decision needs from a menu. */
export function phoneMenuModel(menu: NormalizedActionMenu): PhoneMenuModel {
  const entries = menu.groups.flatMap((g) => g.items)
  return {
    rows: entries.map((e) => ({
      label: e.label,
      reason: e.kind === 'sub' ? undefined : e.disabledReason,
    })),
    headings: menu.groups.flatMap((g) => (g.label ? [g.label] : [])),
    separators: Math.max(0, menu.groups.length - 1),
    hasSubmenu: entries.some((e) => e.kind === 'sub'),
    // The item model has no text fields; a menu that needs one is a picker.
    hasInput: false,
    icons: menu.icons,
  }
}

const OPEN_KEYS = new Set(['Enter', ' ', 'ArrowDown'])

export default function PhoneActionMenu({
  items,
  trigger,
  title,
  label,
  pendingOpen,
}: {
  items: ActionMenuEntry[]
  trigger: React.ReactElement
  title: string
  label: string
  /** A press on the trigger made while this code loaded: opened now. */
  pendingOpen?: PendingOpen
}) {
  const menu = React.useMemo(() => normalizeActionItems(items), [items])
  const model = React.useMemo(() => phoneMenuModel(menu), [menu])
  // Ruled out by the item model alone (too many items, a submenu): always the sheet.
  const mayBeMenu = mayBeAnchoredOnPhone({
    rows: model.rows,
    headings: model.headings.length,
    hasSubmenu: model.hasSubmenu,
    hasInput: model.hasInput,
  })
  const [open, setOpen] = React.useState(false)
  // Mounted after the first open and kept, so the sheet can animate closed.
  const [mounted, setMounted] = React.useState(false)
  const [byKeyboard, setByKeyboard] = React.useState(false)
  const [menuOpen, setMenuOpen] = React.useState(false)
  const triggerRef = React.useRef<HTMLElement | null>(null)
  // A pointer press measured the menu as not fitting: the click opens the sheet.
  const sheetOnClick = React.useRef(false)

  // When the sheet is certain, fetch it while the page is idle, so the first
  // tap opens it at once. A menu that may stay anchored loads it only when a
  // press finds it does not fit.
  React.useEffect(() => {
    if (mayBeMenu || typeof window.requestIdleCallback !== 'function') return
    const id = window.requestIdleCallback(preloadSheet, { timeout: 4000 })
    return () => window.cancelIdleCallback(id)
  }, [mayBeMenu])

  const openSheet = React.useCallback((keyboard: boolean) => {
    setByKeyboard(keyboard)
    setMounted(true)
    setOpen(true)
  }, [])

  // Measured at the moment it opens: the screen, where the trigger is and
  // how wide the labels are in this language.
  const fitsAsMenu = React.useCallback(() => {
    const el = triggerRef.current
    return !!el && measurePhoneFit(el, model) === 'menu'
  }, [model])

  // A press kept while this code loaded opens what that press would have.
  const pendingDone = React.useRef(false)
  React.useEffect(() => {
    if (!pendingOpen || pendingDone.current) return
    pendingDone.current = true
    if (mayBeMenu && fitsAsMenu()) setMenuOpen(true)
    else openSheet(pendingOpen === 'keyboard')
  }, [pendingOpen, mayBeMenu, fitsAsMenu, openSheet])

  const sheet = mounted && (
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
  )

  if (mayBeMenu) {
    const handlers: TriggerHandlers = {
      ref: (el: HTMLButtonElement | null) => {
        triggerRef.current = el
      },
      onPointerDown: (e) => {
        sheetOnClick.current = false
        if (menuOpen || e.button !== 0 || e.ctrlKey || fitsAsMenu()) return
        // Keeps the menu from opening; the sheet opens on the click, so the
        // rest of this tap does not land on its scrim.
        e.preventDefault()
        sheetOnClick.current = true
        preloadSheet()
      },
      onKeyDown: (e) => {
        if (menuOpen || !OPEN_KEYS.has(e.key) || fitsAsMenu()) return
        e.preventDefault()
        openSheet(true)
      },
      onClick: (e) => {
        e.stopPropagation()
        if (!sheetOnClick.current) return
        sheetOnClick.current = false
        openSheet(false)
      },
    }
    return (
      <>
        <AnchoredActionMenu
          items={items}
          trigger={trigger}
          triggerHandlers={handlers}
          open={menuOpen}
          onOpenChange={setMenuOpen}
        />
        {sheet}
      </>
    )
  }

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
      e.stopPropagation()
      if (e.defaultPrevented) return
      // A click with no pointer position came from Enter or Space.
      openSheet(e.detail === 0)
    },
  })

  return (
    <>
      {opener}
      {sheet}
    </>
  )
}
