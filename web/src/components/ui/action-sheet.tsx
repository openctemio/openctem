'use client'

/**
 * The phone renderer of `ActionMenu` (loaded on first use): a bottom sheet
 * titled with the object's name, one 48 px row per action, no icons, groups
 * split by a divider, the destructive group last, submenus drilled into with a
 * Back row. It sits on the bottom of the visible screen, above the browser's
 * own toolbar, with at least 16 px (or the safe area) under its last row. It
 * is a modal dialog (focus trapped and returned, page scroll
 * locked); it closes on the close button, Escape, a tap on the scrim, a swipe
 * down or a chosen action.
 */
import * as React from 'react'
import { Check, ChevronLeft, ChevronRight, X } from 'lucide-react'

import Link from '@/components/link'
import { safeHref } from '@/lib/safe-href'
import { Button } from '@/components/ui/button'
import {
  Drawer,
  DrawerClose,
  DrawerContent,
  DrawerDescription,
  DrawerHandle,
  DrawerTitle,
} from '@/components/ui/drawer'
import type {
  ActionMenuAction,
  ActionMenuGroup,
  ActionMenuSubmenu,
  NormalizedActionMenu,
} from '@/components/ui/action-menu-model'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export type ActionSheetProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  menu: NormalizedActionMenu
  title: string
  label: string
  /** Opened from the keyboard: focus the first row (otherwise the sheet, so no keyboard pops up). */
  focusFirstRow: boolean
  returnFocusTo: React.RefObject<HTMLElement | null>
}

const ROW =
  'flex min-h-12 w-full items-center gap-3 px-4 py-2 text-start text-section font-normal outline-none ' +
  'hover:bg-hov focus-visible:bg-hov focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset'

export default function ActionSheet({
  open,
  onOpenChange,
  menu,
  title,
  label,
  focusFirstRow,
  returnFocusTo,
}: ActionSheetProps) {
  const { t } = useTranslation()
  const [sub, setSub] = React.useState<ActionMenuSubmenu | null>(null)
  const bodyRef = React.useRef<HTMLDivElement>(null)
  const contentRef = React.useRef<HTMLDivElement>(null)

  // Every open starts at the top level.
  React.useEffect(() => {
    if (open) setSub(null)
  }, [open])

  const focusFirst = React.useCallback(() => {
    bodyRef.current?.querySelector<HTMLElement>('[data-slot="action-sheet-row"]')?.focus()
  }, [])

  const openSub = (next: ActionMenuSubmenu | null) => {
    setSub(next)
    // The rows changed under the focus: move it to the first row of the level.
    requestAnimationFrame(focusFirst)
  }

  const choose = (item: ActionMenuAction) => {
    onOpenChange(false)
    item.onSelect?.()
  }

  const lift = useVisibleBottomGap(open)

  const groups: ActionMenuGroup[] = sub ? [{ key: sub.id, items: sub.items }] : menu.groups

  return (
    <Drawer open={open} onOpenChange={onOpenChange}>
      <DrawerContent
        ref={contentRef}
        data-slot="action-sheet"
        // A click in the sheet stays in it (the sheet is portalled, but React
        // events still bubble to the row or card around the trigger).
        onClick={(e) => e.stopPropagation()}
        className="max-h-[calc(85dvh-var(--sheet-lift,0px))] bg-popover pb-[max(1rem,env(safe-area-inset-bottom))] outline-none"
        style={
          lift > 0
            ? ({ bottom: lift, '--sheet-lift': `${lift}px` } as React.CSSProperties)
            : undefined
        }
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          if (focusFirstRow) focusFirst()
          else contentRef.current?.focus()
        }}
        onCloseAutoFocus={(e) => {
          e.preventDefault()
          // An action may have opened a dialog that took the focus: leave it.
          const active = document.activeElement
          if (!active || active === document.body) returnFocusTo.current?.focus()
        }}
        onEscapeKeyDown={(e) => {
          // Escape goes back one level before it closes.
          if (sub) {
            e.preventDefault()
            openSub(null)
          }
        }}
      >
        <DrawerHandle />
        <div className="flex h-12 shrink-0 items-center gap-2 ps-4 pe-2">
          <DrawerTitle className="min-w-0 flex-1 truncate text-body font-medium text-muted-foreground">
            {sub ? sub.label : title}
          </DrawerTitle>
          <DrawerClose asChild>
            <Button variant="ghost" size="icon" aria-label={t('common.actionMenu.close', 'Close')}>
              <X aria-hidden />
            </Button>
          </DrawerClose>
        </div>
        <DrawerDescription className="sr-only">{label}</DrawerDescription>
        <div
          ref={bodyRef}
          data-slot="action-sheet-body"
          className="scroll-cue min-h-0 flex-1 overflow-y-auto overscroll-contain"
        >
          {sub && (
            <button
              type="button"
              data-slot="action-sheet-row"
              className={ROW}
              onClick={() => openSub(null)}
            >
              <ChevronLeft
                className="size-4 shrink-0 text-muted-foreground rtl:rotate-180"
                aria-hidden
              />
              {t('common.actionMenu.back', 'Back')}
            </button>
          )}
          {groups.map((group, i) => (
            <div
              key={group.key}
              role="group"
              aria-label={group.label}
              className={cn(i > 0 && 'mt-2 border-t pt-2')}
            >
              {group.label && (
                <div className="px-4 pt-1 pb-1 text-cap text-muted-foreground" aria-hidden>
                  {group.label}
                </div>
              )}
              {group.items.map((entry) =>
                entry.kind === 'sub' ? (
                  <button
                    key={entry.id}
                    type="button"
                    data-slot="action-sheet-row"
                    className={ROW}
                    onClick={() => openSub(entry)}
                  >
                    <span className="min-w-0 flex-1">{entry.label}</span>
                    <ChevronRight
                      className="size-4 shrink-0 text-muted-foreground rtl:rotate-180"
                      aria-hidden
                    />
                  </button>
                ) : (
                  <SheetRow
                    key={entry.id}
                    item={entry}
                    onChoose={choose}
                    onNavigate={() => onOpenChange(false)}
                  />
                )
              )}
            </div>
          ))}
        </div>
      </DrawerContent>
    </Drawer>
  )
}

/**
 * How far the bottom of the visible screen sits above the layout viewport's
 * bottom (a browser toolbar that overlays the page), measured while the sheet
 * is open. Zero when pinch-zoomed: the zoomed viewport is not a toolbar.
 */
function useVisibleBottomGap(open: boolean): number {
  const [gap, setGap] = React.useState(0)
  React.useEffect(() => {
    const vv = window.visualViewport
    if (!open || !vv) return
    const update = () => {
      const next =
        Math.abs(vv.scale - 1) > 0.01
          ? 0
          : Math.max(0, Math.round(window.innerHeight - vv.offsetTop - vv.height))
      setGap(next)
    }
    update()
    vv.addEventListener('resize', update)
    return () => vv.removeEventListener('resize', update)
  }, [open])
  return gap
}

function SheetRow({
  item,
  onChoose,
  onNavigate,
}: {
  item: ActionMenuAction
  onChoose: (item: ActionMenuAction) => void
  onNavigate: () => void
}) {
  const reasonId = React.useId()
  const tone = item.destructive ? 'text-destructive' : undefined
  if (item.disabledReason) {
    // Focusable and announced as unavailable, with the reason as visible
    // text: there is no hover on a phone.
    return (
      <button
        type="button"
        data-slot="action-sheet-row"
        aria-disabled="true"
        aria-describedby={reasonId}
        className={cn(ROW, 'cursor-default flex-col items-start justify-center gap-0')}
      >
        <span className={cn('opacity-50', tone)}>{item.label}</span>
        <span id={reasonId} className="text-cap text-muted-foreground">
          {item.disabledReason}
        </span>
      </button>
    )
  }
  if (item.href) {
    return (
      <Link
        href={safeHref(item.href) ?? '#'}
        data-slot="action-sheet-row"
        className={cn(ROW, tone)}
        onClick={onNavigate}
      >
        {item.label}
      </Link>
    )
  }
  return (
    <button
      type="button"
      data-slot="action-sheet-row"
      aria-current={item.checked ? 'true' : undefined}
      className={cn(ROW, tone)}
      onClick={() => onChoose(item)}
    >
      <span className="min-w-0 flex-1">{item.label}</span>
      {item.checked && <Check className="size-4 shrink-0" aria-hidden />}
    </button>
  )
}
