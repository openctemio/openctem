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
 * - on a list that takes query text (`query`), a Basic | Query switch at the
 *   field's end (one icon toggle on a phone; Ctrl+/ toggles too). In Query
 *   mode the field is the page's query editor, in the same place and size:
 *   one field, two ways to write the same filter.
 *
 * The component only reports what was typed. A server-side search passes the
 * value through `useSearchQuery` / `useListParams` before it reaches a request
 * (300 ms debounce, minimum length, IME composition); see
 * `hooks/__tests__/search-query-guard.test.ts`.
 */
/** What the query editor needs to sit in the field (`ListSearchQuery.renderEditor`). */
export interface ListSearchFieldSlots {
  /**
   * Classes for the editor's input: room for the icon and the switch. The
   * switch's measured width (plus a gap) is the CSS variable
   * `--list-search-end` on the editor's container, for controls the editor
   * draws before it.
   */
  inputClassName: string
  /** The icon and the mode switch, drawn over the input. */
  adornments: React.ReactNode
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
  inputProps,
}: ListSearchProps) {
  const { t } = useTranslation()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const rootRef = React.useRef<HTMLDivElement>(null)
  const joined = useJoinedStart(rootRef, !!filter)
  const { onKeyDown, ...restInput } = inputProps ?? {}
  const queryActive = !!query?.active
  // Follows the end group that is on screen: Query mode draws it inside the
  // (lazy) editor, so the element changes while the field stays.
  const [end, endRef] = useWidth()
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

  const modeSwitch = query ? (
    <>
      {/* From 768: a two-segment switch, the current mode filled. */}
      <div
        role="group"
        data-slot="list-search-mode"
        aria-label={t('common.listSearch.mode', 'Search mode')}
        className="hidden h-control-seg items-center gap-0.5 rounded-sm bg-muted p-0.5 md:flex"
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
            aria-pressed={queryActive === on}
            title={t('common.listSearch.modeHint', 'Switch between search and query text (Ctrl+/)')}
            onClick={() => queryActive !== on && query.onActiveChange(on)}
            className="h-full rounded-xs px-2 text-xs font-medium text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring aria-pressed:bg-primary aria-pressed:text-primary-foreground"
          >
            {text}
          </button>
        ))}
      </div>
      {/* On a phone: one icon toggle, pressed in Query mode. */}
      <button
        type="button"
        data-slot="list-search-mode"
        aria-pressed={queryActive}
        aria-label={t('common.listSearch.queryMode', 'Query mode')}
        title={t('common.listSearch.queryMode', 'Query mode')}
        onClick={() => query.onActiveChange(!queryActive)}
        className="relative flex size-7 items-center justify-center rounded-sm text-muted-foreground outline-none before:absolute before:inset-[-8px] hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring aria-pressed:bg-primary aria-pressed:text-primary-foreground md:hidden"
      >
        <Code2 className="size-4" aria-hidden="true" />
      </button>
    </>
  ) : null

  const endGroup = (
    <div
      ref={endRef}
      data-slot="list-search-end"
      className={cn(
        'absolute inset-y-0 z-30 flex items-center gap-1',
        query ? 'end-1 md:end-[3px]' : 'end-1.5'
      )}
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
      {modeSwitch}
    </div>
  )
  // The text stops before the end controls (measured: the labels differ by language).
  const fieldStyle = { '--list-search-end': `${Math.max(end + 8, 36)}px` } as React.CSSProperties
  const icon = (Icon: typeof Search) => (
    <Icon
      aria-hidden="true"
      className="pointer-events-none absolute start-3 top-1/2 z-30 size-4 -translate-y-1/2 text-muted-foreground"
    />
  )

  return (
    <div
      ref={rootRef}
      data-slot="list-search"
      data-joined={joined ? '' : undefined}
      className={cn(
        // Grows into the start group's free width, never below 12rem and never
        // wider than 28rem, so the field sits at the same place and size on
        // every list and the end group keeps its room.
        'flex min-w-48 flex-[1_1_16rem] items-start sm:max-w-md',
        // Room for the switch (min 300 with it, as the field's own content).
        query && 'min-w-[min(100%,18.75rem)]',
        queryActive && 'sm:max-w-xl',
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
            adornments: (
              <>
                {icon(Code2)}
                {endGroup}
              </>
            ),
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

/**
 * An element's width, kept current (0 until measured, or in jsdom). A
 * callback ref: it follows whichever element holds it, so an element that is
 * drawn again elsewhere (in the lazy query editor, after its placeholder) is
 * measured again, and a detached one never reports its width as 0.
 */
function useWidth(): [number, (el: HTMLElement | null) => void] {
  const [width, setWidth] = React.useState(0)
  const observer = React.useRef<ResizeObserver | null>(null)
  const ref = React.useCallback((el: HTMLElement | null) => {
    observer.current?.disconnect()
    observer.current = null
    if (!el) return
    const read = () => {
      if (el.isConnected) setWidth(Math.ceil(el.getBoundingClientRect().width))
    }
    read()
    if (typeof ResizeObserver === 'undefined') return
    observer.current = new ResizeObserver(read)
    observer.current.observe(el)
  }, [])
  return [width, ref]
}
