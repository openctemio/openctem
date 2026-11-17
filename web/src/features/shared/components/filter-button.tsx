'use client'

import * as React from 'react'
import { ListFilter, ListFilterPlus, PanelLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The one Filters trigger. Every filter panel, sheet or popover in the app opens
 * from this button, so its look is decided here and nowhere else: an icon-only
 * square (the same size as the toolbar's other icon buttons) with the
 * filter-lines icon, a tooltip, and the active-filter count on its corner.
 *
 * `src/features/shared/components/__tests__/filter-trigger-governance.test.ts`
 * fails the build if a page draws its own filter button.
 */

/** Visible count badge on the button's corner. */
const COUNT_BADGE_CLASS =
  'pointer-events-none absolute -end-1.5 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 text-[10px] leading-none font-medium tabular-nums text-primary-foreground ring-2 ring-background'

/** Tint when at least one filter is applied (theme tokens: works in dark mode). */
const ACTIVE_CLASS =
  'border-primary/50 bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary dark:border-primary/50 dark:bg-primary/15 dark:hover:bg-primary/25'

/** Pressed look while the inline panel it controls is open. */
const PRESSED_CLASS = 'bg-accent text-accent-foreground'

export interface FilterButtonProps extends Omit<
  React.ComponentProps<typeof Button>,
  'children' | 'variant' | 'size' | 'asChild' | 'ref'
> {
  /** Number of filters currently applied; shows the badge and the active tint when > 0. */
  activeCount?: number
  /**
   * Set when the button toggles an inline panel: whether that panel is open.
   * The button reports `aria-pressed` and looks pressed; the icon stays the
   * filter lines on every list (one trigger, one icon).
   * Leave undefined when the button opens a sheet, popover or dialog.
   */
  panelOpen?: boolean
  /** Accessible name and tooltip. Defaults to "Filters". */
  label?: string
}

export const FilterButton = React.forwardRef<HTMLButtonElement, FilterButtonProps>(
  function FilterButton(
    { activeCount = 0, panelOpen, label: labelProp, className, ...props },
    ref
  ) {
    const { t } = useTranslation()
    const label = labelProp ?? t('common.filters', 'Filters')
    const active = activeCount > 0
    const accessibleName = active
      ? t('common.filterButton.active', '{label} ({count} active)', { label, count: activeCount })
      : label
    const tooltip = panelOpen
      ? t('common.filterButton.hide', 'Hide {label}', { label: label.toLowerCase() })
      : label

    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            ref={ref}
            type="button"
            variant="outline"
            size="icon"
            aria-label={accessibleName}
            aria-pressed={panelOpen}
            data-slot="filter-button"
            data-active={active ? '' : undefined}
            className={cn(
              'relative shrink-0',
              panelOpen && PRESSED_CLASS,
              active && ACTIVE_CLASS,
              className
            )}
            {...props}
          >
            <ListFilter className="size-4" aria-hidden="true" />
            {active && (
              // The count is read out through the button's accessible name.
              <span data-slot="filter-count" aria-hidden="true" className={COUNT_BADGE_CLASS}>
                {activeCount > 99 ? '99+' : activeCount}
              </span>
            )}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{tooltip}</TooltipContent>
      </Tooltip>
    )
  }
)

export interface FilterPanelToggleProps {
  /** Whether the inline (large-screen) panel is open. */
  open: boolean
  /** Toggle the inline panel (large screens). */
  onToggle: () => void
  /** Open the filter sheet (below `lg`, where there is no room for the panel). */
  onOpenSheet: () => void
  activeCount: number
  /** `id` of the inline panel this button controls. */
  controlsId: string
  label?: string
  /**
   * The list also has "Add filter": one filter entry per width. From 768 the
   * toolbar has no Filters button (Add filter, right after the search field,
   * opens the panel or the sheet from its last row, `ShowFilterPanelButton`);
   * on a phone this button, joined to the search field, opens the sheet.
   */
  sheetOnly?: boolean
}

/**
 * The Findings filter layout's trigger pair: from `lg` up it toggles the
 * floating side panel, below `lg` it opens the same filters in a sheet. Use this
 * (or `DataTable`'s `filterToggle` prop, which renders it) for every list page
 * with a facet panel.
 */
export function FilterPanelToggle({
  open,
  onToggle,
  onOpenSheet,
  activeCount,
  controlsId,
  label,
  sheetOnly = false,
}: FilterPanelToggleProps) {
  return (
    <>
      {!sheetOnly && (
        <FilterButton
          className="hidden lg:inline-flex"
          panelOpen={open}
          onClick={onToggle}
          // Only while the panel is in the page: an id that points at nothing is
          // an invalid ARIA reference.
          aria-controls={open ? controlsId : undefined}
          activeCount={activeCount}
          label={label}
        />
      )}
      <FilterButton
        className={sheetOnly ? 'md:hidden' : 'lg:hidden'}
        onClick={onOpenSheet}
        aria-haspopup="dialog"
        activeCount={activeCount}
        label={label}
      />
    </>
  )
}

/**
 * The "Add filter" trigger of a list whose filters are chips: an icon-only
 * square at the toolbar's control height (32), solid outline, named "Add
 * filter" with its key `f` in the tooltip. It is the first token, right after
 * the search field: it never changes size, so it never moves when the value
 * tokens after it change (the field stands alone: four round corners). Pass
 * it as the trigger of the list's filter picker (it forwards the trigger's
 * props and ref). From 768 only: on a phone the Filters button joined to the
 * search field is the list's one filter entry.
 */
export function AddFilterButton({
  className,
  ...props
}: Omit<React.ComponentProps<typeof Button>, 'children' | 'variant' | 'size'>) {
  const { t } = useTranslation()
  return (
    <Button
      variant="outline"
      size="icon"
      aria-label={t('common.addFilter.label', 'Add filter')}
      title={t('common.addFilter.hint', 'Add filter (f)')}
      aria-keyshortcuts="f"
      // From 768 only: a phone's one filter entry is the Filters button
      // joined to the search field (`FilterPanelToggle sheetOnly`).
      className={cn('hidden md:inline-flex', className)}
      {...props}
      // After the props: a popover trigger's own slot name must not replace it.
      data-slot="add-filter"
    >
      <ListFilterPlus aria-hidden="true" />
    </Button>
  )
}

/**
 * The last row of an "Add filter" picker on a list that also has a facet
 * panel: opens that panel (beside the list from `lg` up, a sheet below), so
 * the list keeps one filter button on its toolbar and loses no filter.
 */
export function ShowFilterPanelButton({ onClick }: { onClick: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="border-t p-1">
      <Button
        variant="ghost"
        size="sm"
        data-slot="show-filter-panel"
        className="w-full justify-start"
        onClick={onClick}
      >
        <PanelLeft aria-hidden="true" />
        {t('common.addFilter.showPanel', 'Show the filter panel')}
      </Button>
    </div>
  )
}

/** Where a key press belongs to what has the focus, not to the list. */
const SHORTCUT_BLOCKED =
  'input, textarea, select, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="menu"], [role="dialog"], [role="alertdialog"]'

/**
 * The key of "Add filter" (`AddFilterButton` announces it): `f` opens the
 * list's filter picker. Not with a modifier key, not from a field, a menu or
 * a dialog, not while a modal is open, and not in Query mode, where the text
 * owns the filter: pass `enabled={false}` there (a `ListToolbar` whose
 * tokens are inert is skipped as well). `onOpen` may be a new function on
 * every render.
 */
export function useAddFilterShortcut(onOpen: () => void, enabled = true) {
  const open = React.useRef(onOpen)
  React.useEffect(() => {
    open.current = onOpen
  })
  React.useEffect(() => {
    if (!enabled) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'f' || e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return
      // In Query mode the filter tokens are inert: the text owns the filter.
      if (document.querySelector('[data-slot="list-toolbar-tokens"][inert]')) return
      const el = e.target as HTMLElement | null
      if (el?.closest?.(SHORTCUT_BLOCKED)) return
      // A modal on top owns the keyboard.
      if (document.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"]')) return
      e.preventDefault()
      open.current()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [enabled])
}
