'use client'

import * as React from 'react'
import { Code2, Search, X } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The one search box of a list (research/267). Every list toolbar draws its
 * search with this, so the field looks and behaves the same on every page:
 *
 * - 36px high, the search icon at the start, the placeholder "Search <fields>…"
 *   naming what is matched, an accessible name of its own;
 * - a clear button while there is text; Escape clears it too;
 * - `/` anywhere on the page (outside a text field) focuses it (`ListToolbar`
 *   routes the key to the first toolbar on the page);
 * - when the list has a filter panel, its trigger is passed as `filter` and is
 *   joined to the start of the field: one control, never split by a wrap. The
 *   join follows what is drawn, not what is passed: a trigger hidden at this
 *   width (a sheet-only trigger on a desktop) leaves the field with four round
 *   corners; a shown one squares the two inner corners only.
 *
 * - on a list that takes query text (`query`), a Basic | Query switch drawn
 *   as its own control right before the field (and before a joined filter
 *   trigger): a two-segment switch on a wide toolbar, one icon toggle below;
 *   Ctrl+/ toggles too. Its width is fixed per language, so the switch never
 *   moves. In Query mode the field is the page's query editor, in the same
 *   place, and it takes all the room the row has (the filter tokens step
 *   aside, `ListToolbar`), so a query is read on one long line: one field,
 *   two ways to write the same filter.
 *
 * The component only reports what was typed. A server-side search passes the
 * value through `useSearchQuery` / `useListParams` before it reaches a request
 * (300 ms debounce, minimum length, IME composition); see
 * `hooks/__tests__/search-query-guard.test.ts`.
 */
/** What the query editor needs to sit in the field (`ListSearchQuery.renderEditor`). */
export interface ListSearchFieldSlots {
  /**
   * Classes for the editor's input: room for the icon and the field's end.
   * The room the host keeps at the end is the CSS variable
   * `--list-search-end` on the editor's container, for controls the editor
   * draws there.
   */
  inputClassName: string
  /** The icon (and any host end controls), drawn over the input. */
  adornments: React.ReactNode
  /** Where the editor draws its problem line, when the field sits in a `ListToolbar`. */
  status?: ListSearchStatusSlot
}

/**
 * The status row a list toolbar keeps under itself for its query field: the
 * editor draws its problem line into `host` (a portal) and says when it has
 * one to show, so the row takes its place only then.
 */
export interface ListSearchStatusSlot {
  host: HTMLElement | null
  onDrawnChange: (drawn: boolean) => void
}

/** The field's Query mode, on a list whose filter can be written as query text. */
export interface ListSearchQuery {
  /** Query mode is on. */
  active: boolean
  /** Switch modes (the page converts the filter between the two). */
  onActiveChange: (active: boolean) => void
  /** The query editor, drawn in place of the input in Query mode. */
  renderEditor: (slots: ListSearchFieldSlots) => React.ReactNode
}

export interface ListSearchProps {
  value: string
  onChange: (value: string) => void
  /** "Search <fields>…", naming what the search matches. */
  placeholder: string
  /** Accessible name, e.g. "Search findings". Defaults to the placeholder. */
  label?: string
  /** The list's filter trigger (`FilterButton` / `FilterPanelToggle`), joined to the field's start. */
  filter?: React.ReactNode
  className?: string
  /** Query mode, where the list takes query text. */
  query?: ListSearchQuery
  /** The toolbar's status row (set by `ListToolbar`, never by a page). */
  statusSlot?: ListSearchStatusSlot
  /** Extra props for the input (e.g. `data-testid`, `onKeyDown`). */
  inputProps?: Omit<
    React.ComponentProps<typeof Input>,
    'value' | 'onChange' | 'placeholder' | 'className' | 'type'
  >
}

export function ListSearch({
  value,
  onChange,
  placeholder,
  label,
  filter,
  className,
  query,
  statusSlot,
  inputProps,
}: ListSearchProps) {
  const { t } = useTranslation()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const rootRef = React.useRef<HTMLDivElement>(null)
  const joined = useJoinedStart(rootRef, !!filter)
  const { onKeyDown, ...restInput } = inputProps ?? {}
  const queryActive = !!query?.active
  const setQueryActive = query?.onActiveChange
  const hasQuery = !!query

  // Ctrl+/ (Cmd+/) switches modes anywhere on the page.
  React.useEffect(() => {
    if (!hasQuery || !setQueryActive) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && (e.ctrlKey || e.metaKey) && !e.altKey) {
        e.preventDefault()
        setQueryActive(!queryActive)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [hasQuery, setQueryActive, queryActive])

  const endGroup = (
    <div
      data-slot="list-search-end"
      className="absolute inset-y-0 end-1.5 z-30 flex items-center gap-1"
    >
      {value && !queryActive ? (
        <button
          type="button"
          data-slot="list-search-clear"
          aria-label={t('common.listSearch.clear', 'Clear search')}
          onClick={() => {
            onChange('')
            inputRef.current?.focus()
          }}
          className="flex size-6 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <X className="size-3.5" aria-hidden="true" />
        </button>
      ) : null}
    </div>
  )
  // The text stops before the end controls. Basic: the clear button's room,
  // kept while the field is empty so the first character moves nothing.
  // Query: the editor draws its own controls (help, expand, run) at the end.
  const fieldStyle = {
    '--list-search-end': queryActive ? '0.5rem' : '2.25rem',
  } as React.CSSProperties
  const icon = (Icon: typeof Search) => (
    <Icon
      aria-hidden="true"
      className="pointer-events-none absolute start-3 top-1/2 z-30 size-4 -translate-y-1/2 text-muted-foreground"
    />
  )

  const field = (
    <div
      ref={rootRef}
      data-slot="list-search"
      data-joined={joined ? '' : undefined}
      className={cn(
        // Grows into the start group's free width, never below 12rem and never
        // wider than 28rem, so the field sits at the same place and size on
        // every list and the end group keeps its room.
        'flex min-w-48 flex-[1_1_16rem] items-start group-data-[fold=true]/toolbar:basis-48 sm:max-w-md',
        // With the mode switch beside it the field asks for 11rem before it
        // grows (a line breaks on that ask, never below the floor), so the
        // switch, the field and the filter tokens (each of a fixed width)
        // keep one line on a 720 px toolbar. A phone's field takes what its
        // line leaves after the toggle.
        query && 'min-w-44 flex-[1_1_11rem] @max-md/toolbar:min-w-0',
        // Query mode: the editor takes the row's free width (not the 28rem
        // search cap), so a query is read on one long line, not wrapped; at
        // most a long text field's width (60rem), so it never stretches
        // across a wide screen.
        queryActive && 'flex-[1_1_16rem] sm:max-w-(--field-max-multiline)',
        filter && '[&_[data-slot=filter-button]]:z-10 [&_[data-slot=filter-button]]:rounded-e-none',
        className
      )}
    >
      {filter}
      {queryActive && query ? (
        <div
          data-slot="list-search-query"
          className={cn('min-w-0 flex-1', joined && '-ms-px')}
          style={fieldStyle}
        >
          {query.renderEditor({
            inputClassName: cn('ps-9 pe-(--list-search-end)', joined && 'rounded-s-none'),
            adornments: icon(Code2),
            status: statusSlot,
          })}
        </div>
      ) : (
        <div
          data-slot="list-search-field"
          className={cn('relative min-w-0 flex-1', joined && '-ms-px')}
          style={fieldStyle}
        >
          {icon(Search)}
          <Input
            ref={inputRef}
            type="search"
            data-slot="list-search-input"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape' && value) {
                e.preventDefault()
                e.stopPropagation()
                onChange('')
              }
              onKeyDown?.(e)
            }}
            placeholder={placeholder}
            aria-label={label ?? placeholder}
            aria-keyshortcuts="/"
            inputMode="search"
            enterKeyHint="search"
            className={cn(
              // The native clear control is replaced by ours (one look in every browser).
              'ps-9 pe-(--list-search-end) focus-visible:z-20 [&::-webkit-search-cancel-button]:appearance-none',
              joined && 'rounded-s-none'
            )}
            {...restInput}
          />
          {endGroup}
        </div>
      )}
    </div>
  )
  if (!query) return field
  return (
    <>
      <ListSearchModeSwitch
        mode={queryActive ? 'query' : 'basic'}
        onModeChange={(m) => query.onActiveChange(m === 'query')}
      />
      {field}
    </>
  )
}

/** The search mode of a list field. */
export type ListSearchMode = 'basic' | 'query'

/**
 * The Basic | Query switch, its own control right before the search field.
 * On a toolbar of 64rem and more (1440 px with the sidebar) a two-segment
 * switch: both segments as wide as the longer label (one grid track each), so
 * its width is fixed per language and never follows the mode. On a narrower
 * toolbar one icon toggle (32 px, 36 on a phone), pressed in Query mode, so
 * the field and the filter tokens keep their room on one line. Which one
 * shows follows the toolbar's width only, never what it holds. `ListSearch`
 * draws it for a list with `query`.
 */
export function ListSearchModeSwitch({
  mode,
  onModeChange,
}: {
  mode: ListSearchMode
  onModeChange: (mode: ListSearchMode) => void
}) {
  const { t } = useTranslation()
  const active = mode === 'query'
  const onActiveChange = (on: boolean) => onModeChange(on ? 'query' : 'basic')
  const hint = t('common.listSearch.modeHint', 'Switch between search and query text (Ctrl+/)')
  return (
    <>
      <div
        role="group"
        data-slot="list-search-mode"
        aria-label={t('common.listSearch.mode', 'Search mode')}
        className="hidden h-control shrink-0 auto-cols-fr grid-flow-col items-center gap-0.5 rounded-md border p-0.5 @5xl/toolbar:inline-grid"
      >
        {(
          [
            [false, t('common.listSearch.basic', 'Basic')],
            [true, t('common.listSearch.query', 'Query')],
          ] as const
        ).map(([on, text]) => (
          <button
            key={String(on)}
            type="button"
            data-slot={on ? 'list-search-mode-query' : 'list-search-mode-basic'}
            aria-pressed={active === on}
            aria-keyshortcuts="Control+/"
            title={hint}
            onClick={() => active !== on && onActiveChange(on)}
            className="h-control-seg rounded-sm px-2.5 text-xs font-medium whitespace-nowrap text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring aria-pressed:bg-primary aria-pressed:text-primary-foreground"
          >
            {text}
          </button>
        ))}
      </div>
      <button
        type="button"
        data-slot="list-search-mode"
        aria-pressed={active}
        aria-keyshortcuts="Control+/"
        aria-label={t('common.listSearch.queryMode', 'Query mode')}
        title={t('common.listSearch.queryMode', 'Query mode')}
        onClick={() => onActiveChange(!active)}
        className="flex size-control shrink-0 items-center justify-center rounded-md border text-muted-foreground outline-none hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring aria-pressed:border-primary aria-pressed:bg-primary aria-pressed:text-primary-foreground max-md:size-control-touch @5xl/toolbar:hidden"
      >
        <Code2 className="size-4 max-md:size-5" aria-hidden="true" />
      </button>
    </>
  )
}

/**
 * Whether a control passed before the field is drawn at this width. The filter
 * trigger hides by breakpoint (`hidden lg:inline-flex`, `lg:hidden`), which
 * only its own classes know, so the join is read from the page: each child
 * before the field is observed, and a size change (shown or hidden by a
 * breakpoint) reads it again. Not joined until measured (server render, jsdom
 * without layout): four round corners is the safe default.
 */
function useJoinedStart(ref: React.RefObject<HTMLElement | null>, hasStart: boolean): boolean {
  const [joined, setJoined] = React.useState(false)
  React.useLayoutEffect(() => {
    const root = ref.current
    if (!root || !hasStart) {
      setJoined(false)
      return
    }
    const starts = () =>
      Array.from(root.children).filter(
        (el): el is HTMLElement =>
          el instanceof HTMLElement &&
          el.dataset.slot !== 'list-search-field' &&
          el.dataset.slot !== 'list-search-query'
      )
    const read = () => setJoined(starts().some((el) => el.getClientRects().length > 0))
    read()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(read)
    for (const el of starts()) ro.observe(el)
    return () => ro.disconnect()
  }, [ref, hasStart])
  return joined
}
