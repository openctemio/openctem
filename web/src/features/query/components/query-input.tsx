'use client'

/**
 * QueryInput: the one search box for filtered lists and custom queries
 * (server/docs/architecture/query-language.md, "Short form"). People type plain
 * words (a text search) or conditions such as
 * `severity>=high kev=true -status:accepted last_seen<7d`; the long form
 * (`findings where ...`) is accepted too. The text is plain text: nothing is
 * rendered as HTML.
 *
 * Typing sends nothing to the server. Fields, operators and enum values come
 * from the entity's schema, read once and kept for the session; the caret's
 * context is read here; quotes and parentheses are checked here. The server
 * checks the text once, when it is applied (Enter, Ctrl/Cmd+Enter in a text
 * area, or the Apply button), and its first problem shows under the box with
 * its fix. Values only the server knows (tools, CVEs, domains) are asked for
 * after two characters or Ctrl+Space, 300 ms after the last key, and a newer
 * key cancels the request in flight.
 */

import {
  forwardRef,
  useCallback,
  useEffect,
  useLayoutEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { CircleHelp, Maximize2, Minimize2, MoreHorizontal, Play } from 'lucide-react'
import { ActionMenu } from '@/components/ui/action-menu'
import { Popover, PopoverAnchor, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { containingOverlay } from '@/components/ui/floating'
import type { ListSearchStatusSlot } from '@/features/shared/components/list-search'
import { TOKEN_CLASSES } from '@/lib/code-tokens'
import { cn } from '@/lib/utils'
import {
  queryApi,
  useQuerySchema,
  type ParseResult,
  type QueryEntity,
  type QueryProblem,
} from '../api/query-api'
import {
  applyCompletion,
  applyFix,
  contextAt,
  fieldByName,
  fieldCompletions,
  formatCount,
  localProblem,
  localValues,
  quoteValue,
  shortOperators,
  type CaretContext,
  type Completion,
  type LocalProblem,
} from '../lib/complete'
import { queryTokens } from '../lib/highlight'
import { pushRecent, readRecent } from '../lib/recent'
import { SuggestionList } from './suggestion-list'

/** Value lookup delay after the last key. */
export const VALUES_DELAY_MS = 300
/** Characters of a value typed before the server is asked for values (Ctrl+Space asks at once). */
export const VALUES_MIN_PREFIX = 2
const MAX_OPTIONS = 10

/**
 * The expanded editor follows its text: two lines at least (room for the next
 * condition), eight at most (or half the screen), then it scrolls inside.
 */
export const EDITOR_MIN_LINES = 2
export const EDITOR_MAX_LINES = 8
/** Its height animates this long when it opens or folds (none with reduced motion). */
export const EDITOR_ANIMATION_MS = 200
/** Room kept under it on a short screen: the top of the list stays in reach. */
const EDITOR_KEEP_BELOW = 104
// Room for the field's own controls and the host's (phone: overflow and run,
// 2 x 28 px; from 768: help, expand, run, 3 x 24 px).
const FIELD_CONTROLS_ROOM =
  'pe-[calc(var(--list-search-end,0.5rem)+3.75rem)] md:pe-[calc(var(--list-search-end,0.5rem)+4.75rem)]'

function reducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  )
}

/**
 * The suggestion list is a kit popover in a portal, so a dialog body or any
 * other scroll container never clips it. It lines up with the start of the
 * field and its status line (the hint or the problem stays readable), opens
 * below them, or above the field when there is no room below, is never wider
 * than the field (28rem at most) and never taller than the room on its side
 * (16rem at most, about ten rows), scrolling inside.
 */
export const SUGGESTION_LIST_CLASSES =
  'w-[min(28rem,var(--radix-popover-trigger-width))] min-w-0 max-h-[min(16rem,var(--radix-popover-content-available-height))] overflow-y-auto p-1'

/**
 * Below 768 px a list field shares its line with the mode toggle and the
 * Filters button, so a list as wide as the field cramps every row. There the
 * list spans the screen less the popover's gutters (the page gutter, or the
 * safe area when that is wider; the kit's collision padding puts its start on
 * the gutter) and shows about eight one-line rows. A field inside a dialog,
 * sheet or popover keeps the field's width, so the list never leaves it.
 */
export const SUGGESTION_LIST_PHONE_CLASSES =
  'max-md:w-[calc(100vw-var(--float-gutter-x,2rem))] max-md:max-h-[min(17rem,var(--radix-popover-content-available-height))]'

export interface QueryInputProps {
  entity: QueryEntity
  value: string
  onChange: (text: string) => void
  /**
   * Apply: Enter (Ctrl/Cmd+Enter in a text area) or the Apply button. The
   * server checks the text once; a valid answer is handed over, a refusal
   * shows under the box.
   */
  onSubmit?: (result: ParseResult) => void
  /**
   * The text that is in force (a list's current filter). With `onSubmit` the
   * box shows an Apply button, enabled while the text differs from it, and
   * says the edit is not applied yet.
   */
  applied?: string
  /**
   * A server answer the owner of the box obtained for the current text (a
   * mode switch, a preview): its problem shows under the box. The owner
   * clears it when the text changes.
   */
  checked?: ParseResult | null
  /** Recent queries are kept per scope (an entity and tab, "findings"). */
  recentScope?: string
  /** The result count of the current filter, shown under the box. */
  resultCount?: number | null
  /** A text area for long queries (custom query dialogs). */
  multiline?: boolean
  placeholder?: string
  id?: string
  autoFocus?: boolean
  disabled?: boolean
  className?: string
  /** Accessible name when no visible label points at the box. */
  ariaLabel?: string
  /** Fields completion lists first (the open tab's own fields). */
  preferFields?: string[]
  /** Extra classes for the input (a list search field leaves room for its icons). */
  inputClassName?: string
  /** Controls drawn over the input (a list search field's icon and mode switch). */
  adornments?: ReactNode
  /**
   * Show only problems under the box (a list toolbar keeps one line): the
   * hint, the check and the result count are still read out, not drawn.
   */
  quietStatus?: boolean
  /**
   * Where a quiet field draws its problem line: the status row the list
   * toolbar keeps under itself, so the toolbar row keeps its height. Without
   * it the line shows under the field.
   */
  statusSlot?: ListSearchStatusSlot
  /** Escape with no suggestion open (a list search field reverts its text). */
  onEscape?: () => void
}

export function QueryInput({
  entity,
  value,
  onChange,
  onSubmit,
  applied,
  checked,
  recentScope,
  resultCount,
  multiline,
  placeholder,
  id,
  autoFocus,
  disabled,
  className,
  ariaLabel,
  preferFields,
  inputClassName,
  adornments,
  quietStatus,
  statusSlot,
  onEscape,
}: QueryInputProps) {
  const { t, locale } = useTranslation()
  const ownId = useId()
  const inputId = id ?? `${ownId}-input`
  const listId = `${ownId}-list`
  const statusId = `${ownId}-status`
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null)
  const anchorRef = useRef<HTMLDivElement>(null)
  // `autoFocus` focuses the field once, as soon as it can take the focus
  // (a list's editor is disabled while its text is printed); swapping the
  // one-line field and the expanded editor moves the focus by hand (setBig).
  const focusedOnce = useRef(false)
  // The syntax help, opened from its button or from a phone's overflow.
  const [helpOpen, setHelpOpen] = useState(false)
  const controlsRef = useRef<HTMLDivElement>(null)
  // A field in a dialog, sheet or popover: its suggestions keep its width.
  const [inOverlay, setInOverlay] = useState(false)
  useLayoutEffect(() => {
    const el = anchorRef.current
    setInOverlay(!!el && !!containingOverlay(el))
  }, [])
  useEffect(() => {
    if (!autoFocus || disabled || focusedOnce.current) return
    focusedOnce.current = true
    ref.current?.focus()
  }, [autoFocus, disabled])
  const listAnchor = useMemo(
    () => ({
      current: {
        getBoundingClientRect: () => anchorRef.current?.getBoundingClientRect() ?? new DOMRect(),
      },
    }),
    []
  )
  const { data: schema } = useQuerySchema(entity, !disabled)
  const fields = useMemo(() => {
    const all = schema?.fields ?? []
    if (!preferFields?.length) return all
    // The page's own fields (an inventory tab's) lead the common group.
    const first = new Set(preferFields)
    return [
      ...all.filter((f) => first.has(f.path)).map((f) => ({ ...f, group: 'common' })),
      ...all.filter((f) => !first.has(f.path)),
    ]
  }, [schema, preferFields])
  const scope = recentScope ?? entity

  const [caret, setCaret] = useState(0)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  // A row was picked with the arrows since the last edit.
  const arrowed = useRef(false)
  // Ctrl+Space: values are asked for at once, whatever was typed.
  const [explicit, setExplicit] = useState(false)
  // The list field's expanded editor: the field itself grows in place, in
  // the page's flow (what is below moves down), and the text it opened with
  // (Escape folds it back when unchanged). Opening and folding animate the
  // height (`animating`); open, its height follows its text (`textH`).
  const [phase, setPhase] = useState<'closed' | 'opening' | 'open' | 'closing'>('closed')
  const big = phase !== 'closed'
  const [animating, setAnimating] = useState(false)
  const [bigFrom, setBigFrom] = useState('')
  const [fieldH, setFieldH] = useState(32)
  const [lineH, setLineH] = useState(20)
  // The height the text takes at the editor's width (paddings and borders included).
  const [textH, setTextH] = useState<number | null>(null)
  // The room on screen below the editor's top (a phone keyboard, a zoomed
  // page), so the run icon and the top of the list stay reachable.
  const [room, setRoom] = useState(Number.POSITIVE_INFINITY)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pendingFocus = useRef<[number, number] | null>(null)
  useEffect(() => () => clearTimeout(timer.current ?? undefined), [])
  const frame = fieldH - lineH // the editor's paddings and borders
  const maxH = Math.max(
    frame + 2 * lineH,
    Math.min(
      frame + EDITOR_MAX_LINES * lineH,
      typeof window === 'undefined' ? Infinity : window.innerHeight / 2,
      room
    )
  )
  const minH = Math.min(frame + EDITOR_MIN_LINES * lineH, maxH)
  const openH = Math.round(Math.min(maxH, Math.max(minH, textH ?? minH)))
  const setBig = (on: boolean) => {
    const el = ref.current
    const from = el?.selectionStart ?? value.length
    const to = el?.selectionEnd ?? from
    clearTimeout(timer.current ?? undefined)
    setOpen(false)
    setAnimating(true)
    const settle = reducedMotion() ? 0 : EDITOR_ANIMATION_MS + 20
    if (on) {
      if (el) {
        setFieldH(el.offsetHeight || 32)
        setLineH(parseFloat(getComputedStyle(el).lineHeight) || 20)
      }
      setBigFrom(value)
      setPhase('opening')
      timer.current = setTimeout(() => setAnimating(false), settle)
    } else {
      // One line cannot hold a line break: each becomes a space, so the
      // conditions stay apart and the caret keeps its place.
      if (/[\r\n]/.test(value)) onChange(value.replace(/[\r\n]/g, ' '))
      setPhase('closing')
      timer.current = setTimeout(() => {
        setPhase('closed')
        setAnimating(false)
      }, settle)
    }
    // The focus and selection move to the element drawn next (below).
    pendingFocus.current = [from, to]
  }
  // Opening: the editor is drawn at the field's height first, then grows.
  useLayoutEffect(() => {
    if (phase === 'opening') {
      void ref.current?.offsetHeight // the start height, so the change animates
      setPhase('open')
    }
    if (phase !== 'opening' && phase !== 'closed') return
    const sel = pendingFocus.current
    const next = ref.current
    pendingFocus.current = null
    // On a touch screen the keyboard opens only when the person taps the text.
    if (!sel || !next || coarsePointer()) return
    next.focus()
    next.setSelectionRange(sel[0], sel[1])
    setCaret(sel[0])
  }, [phase])
  // The editor follows the visual viewport (a phone keyboard, a zoomed page).
  useEffect(() => {
    const vv = typeof window === 'undefined' ? null : window.visualViewport
    if (!big || !vv) return
    const fit = () => {
      const top = ref.current?.getBoundingClientRect().top
      if (top === undefined) return
      setRoom(Math.floor(vv.offsetTop + vv.height - top - EDITOR_KEEP_BELOW))
    }
    fit()
    vv.addEventListener('resize', fit)
    vv.addEventListener('scroll', fit)
    return () => {
      vv.removeEventListener('resize', fit)
      vv.removeEventListener('scroll', fit)
    }
  }, [big])
  // The text's height, read from the coloured copy behind the editor (same
  // box, same width, never cut short by the editor's own height): on every
  // edit, and again when the editor's width changes (the lines wrap anew).
  useLayoutEffect(() => {
    const el = ref.current
    const copy = el?.previousElementSibling
    if (!big || !el || !(copy instanceof HTMLElement)) return
    const read = () => {
      const h = copy.scrollHeight + (copy.offsetHeight - copy.clientHeight)
      if (h > 0) setTextH(h)
    }
    read()
    if (typeof ResizeObserver === 'undefined') return
    let width = el.offsetWidth
    const ro = new ResizeObserver(() => {
      if (el.offsetWidth === width) return
      width = el.offsetWidth
      read()
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [big, value])
  // The server's answer to the text it was asked about on Apply.
  const [answer, setAnswer] = useState<{ text: string; result: ParseResult } | null>(null)
  // Apply refused before asking (quotes or parentheses do not pair up).
  const [refused, setRefused] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)
  const [failed, setFailed] = useState<string | null>(null)
  const [remote, setRemote] = useState<{ key: string; options: Completion[] } | null>(null)

  const ctx: CaretContext = useMemo(() => contextAt(value, caret), [value, caret])
  const field = useMemo(
    () => (ctx.kind === 'value' ? fieldByName(fields, ctx.path) : undefined),
    [ctx, fields]
  )
  const remoteKey = ctx.kind === 'value' ? `${ctx.path}\u0000${ctx.prefix}\u0000${ctx.rest}` : ''
  const needsRemote =
    open &&
    ctx.kind === 'value' &&
    !!ctx.path &&
    localValues(field, ctx) === null &&
    (explicit || ctx.prefix.length >= VALUES_MIN_PREFIX)

  // Values of string fields (tools, CVEs, domains): the server's top values
  // in the caller's scope, under the rest of the filter. Only on demand, after
  // a pause; the next key cancels the request in flight.
  useEffect(() => {
    if (!needsRemote || !ctx.path) return
    const abort = new AbortController()
    const timer = setTimeout(() => {
      queryApi
        .values(entity, ctx.path ?? '', ctx.prefix, ctx.rest, abort.signal)
        .then((res) => {
          if (abort.signal.aborted) return
          setRemote({
            key: remoteKey,
            options: res.values.slice(0, MAX_OPTIONS).map((v) => ({
              kind: 'value' as const,
              label: String(v.value),
              insert: quoteValue(String(v.value)),
              count: res.counted ? v.count : undefined,
            })),
          })
        })
        .catch(() => {
          if (!abort.signal.aborted) setRemote({ key: remoteKey, options: [] })
        })
    }, VALUES_DELAY_MS)
    return () => {
      clearTimeout(timer)
      abort.abort()
    }
  }, [needsRemote, remoteKey, entity, ctx.path, ctx.prefix, ctx.rest])

  const options: Completion[] = useMemo(() => {
    if (!open) return []
    if (value.trim() === '') {
      const recent = readRecent(scope).slice(0, MAX_OPTIONS)
      // An empty field offers the recent queries, or the fields to start from.
      if (recent.length > 0)
        return recent.map((r) => ({ kind: 'recent' as const, label: r, insert: r }))
      return fieldCompletions(contextAt('', 0), fields)
    }
    if (ctx.kind === 'field') return fieldCompletions(ctx, fields, MAX_OPTIONS)
    if (ctx.kind === 'value') {
      const local = localValues(field, ctx)
      if (local) return local.slice(0, MAX_OPTIONS)
      return remote?.key === remoteKey ? remote.options : []
    }
    return []
  }, [open, value, ctx, fields, field, remote, remoteKey, scope])

  const setText = useCallback(
    (text: string, nextCaret: number) => {
      onChange(text)
      requestAnimationFrame(() => {
        ref.current?.setSelectionRange(nextCaret, nextCaret)
        setCaret(nextCaret)
      })
    },
    [onChange]
  )

  const accept = (o: Completion) => {
    if (o.kind === 'recent') {
      setText(o.insert, o.insert.length)
      setOpen(false)
      return
    }
    const next = applyCompletion(value, ctx, o.insert)
    setText(next.text, next.caret)
    setActive(0)
    // After a field or an operator the next suggestions follow at once.
    setOpen(o.kind === 'field' || o.kind === 'operator')
  }

  /** Selects a range of the text: the field scrolls to it, typing replaces it. */
  const select = (start: number, end: number) => {
    const el = ref.current
    if (!el) return
    const s = Math.min(start, value.length)
    el.focus()
    el.setSelectionRange(s, Math.max(s, Math.min(end, value.length)))
    setCaret(s)
  }

  const submit = () => {
    if (!onSubmit || checking) return
    const text = value
    if (text.trim() === '') {
      onSubmit({
        entity,
        valid: true,
        text: '',
        query: '',
        chips: [],
        advanced: false,
        problems: [],
      })
      return
    }
    // The suggestions close so the problem line shows.
    setOpen(false)
    const local = localProblem(text)
    if (local) {
      // A text that cannot be read is not sent.
      setRefused(text)
      select(local.start, local.end)
      return
    }
    setRefused(null)
    setFailed(null)
    setChecking(true)
    queryApi
      .parse({ entity, text })
      .then((res) => {
        setAnswer({ text, result: res })
        if (res.valid) {
          pushRecent(scope, res.text || text)
          onSubmit(res)
          return
        }
        const p = res.problems[0]
        if (p) select(p.start, p.end)
      })
      .catch(() => setFailed(text))
      .finally(() => setChecking(false))
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const listOpen = options.length > 0
    if (e.key === ' ' && e.ctrlKey) {
      e.preventDefault()
      setExplicit(true)
      setOpen(true)
      return
    }
    if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && listOpen) arrowed.current = true
    if (e.key === 'ArrowDown' && listOpen) {
      e.preventDefault()
      setActive((a) => (a + 1) % options.length)
    } else if (e.key === 'ArrowUp' && listOpen) {
      e.preventDefault()
      setActive((a) => (a - 1 + options.length) % options.length)
    } else if (e.key === 'ArrowUp' && value === '') {
      const last = readRecent(scope)[0]
      if (last) {
        e.preventDefault()
        setText(last, last.length)
      }
    } else if (e.key === 'Tab' && listOpen) {
      e.preventDefault()
      accept(options[Math.min(active, options.length - 1)])
    } else if (e.key === 'Enter' && !e.shiftKey) {
      // An empty field lists the fields to start from; Enter there still
      // applies the empty query (no filter) unless a row was picked with the
      // arrows.
      const browsing = value.trim() === '' && options[0]?.kind === 'field' && !arrowed.current
      if (listOpen && !browsing && !e.ctrlKey && !e.metaKey) {
        e.preventDefault()
        accept(options[Math.min(active, options.length - 1)])
      } else if (!multiline || e.ctrlKey || e.metaKey) {
        e.preventDefault()
        submit()
      }
    } else if (e.key === 'Escape') {
      if (listOpen) {
        e.stopPropagation()
        setOpen(false)
      } else if (
        big &&
        (value === bigFrom || (applied !== undefined && value.trim() === applied.trim()))
      ) {
        // The expanded editor folds back first when nothing is left unapplied.
        e.preventDefault()
        e.stopPropagation()
        setBig(false)
      } else if (onEscape) {
        e.preventDefault()
        e.stopPropagation()
        onEscape()
      } else {
        ref.current?.blur()
      }
    }
  }

  // The server's word on this very text: from Apply, or from the box's owner.
  const server = answer?.text === value ? answer.result : (checked ?? null)
  const problem = server && !server.valid ? server.problems[0] : undefined
  // Pairing problems are found while typing; they are drawn as a problem
  // once Apply was refused for them, and read out (muted) before that.
  const local = problem ? null : localProblem(value)
  const localShown = !!local && refused === value
  const dirty = applied !== undefined && value.trim() !== applied.trim()
  // A list field (one line, with an applied filter) carries its controls in
  // the field: syntax help, expand, run.
  const inline = !multiline && !!onSubmit && applied !== undefined
  const expanded = options.length > 0
  const shared = {
    id: inputId,
    value,
    disabled,
    spellCheck: false,
    autoComplete: 'off',
    maxLength: 4096,
    placeholder: placeholder ?? t(`queryInput.placeholder.${entity}`),
    role: 'combobox',
    'aria-label': ariaLabel,
    'aria-autocomplete': 'list' as const,
    'aria-expanded': expanded,
    'aria-controls': expanded ? listId : undefined,
    'aria-activedescendant': expanded ? `${listId}-${active}` : undefined,
    'aria-describedby': statusId,
    'aria-invalid': !!problem || localShown,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      onChange(e.target.value)
      setCaret(e.target.selectionStart ?? e.target.value.length)
      setActive(0)
      arrowed.current = false
      setExplicit(false)
      setOpen(true)
    },
    onKeyDown,
    onClick: (e: React.MouseEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setCaret(e.currentTarget.selectionStart ?? 0),
    onFocus: () => setOpen(true),
    onBlur: () => setOpen(false),
  }

  const drawn = !!problem || localShown || failed === value
  // A list toolbar's field hands its problem line to the toolbar's status
  // row: one line of the row's height, so the toolbar row never grows.
  const slotted = !!quietStatus && !!statusSlot
  const statusHost = slotted ? (statusSlot?.host ?? null) : null
  const reportDrawn = statusSlot?.onDrawnChange
  const slotDrawn = slotted && drawn
  useEffect(() => {
    reportDrawn?.(slotDrawn)
  }, [reportDrawn, slotDrawn])
  useEffect(() => () => reportDrawn?.(false), [reportDrawn])
  const unavailable = t('queryInput.unavailable')
  const statusLine = (
    <div
      id={statusId}
      aria-live="polite"
      data-slot="query-status"
      data-drawn={quietStatus && drawn ? '' : undefined}
      className={cn(
        'text-muted-foreground text-xs',
        slotted
          ? // In the toolbar's status row; read out only until there is a problem.
            drawn && statusHost
            ? 'flex min-w-0 flex-1 items-center'
            : 'sr-only'
          : // A list field adds no space under itself until there is a problem.
            cn('min-h-5', quietStatus && (drawn ? 'mt-1' : 'sr-only'))
      )}
    >
      {problem ? (
        <ProblemLine
          problem={problem}
          row={slotted}
          onFix={(fix) =>
            setText(applyFix(value, problem.start, problem.end, fix), problem.start + fix.length)
          }
        />
      ) : local ? (
        <LocalProblemLine problem={local} text={value} strong={localShown} row={slotted} />
      ) : checking ? (
        <span>{t('queryInput.checking')}</span>
      ) : failed === value ? (
        <span
          className={slotted ? 'min-w-0 truncate' : undefined}
          title={slotted ? unavailable : undefined}
        >
          {unavailable}
        </span>
      ) : dirty ? (
        <span>{t('queryInput.pending')}</span>
      ) : typeof resultCount === 'number' && value.trim() !== '' ? (
        <span>
          {t('queryInput.results', undefined, { count: formatCount(resultCount, locale) })}
        </span>
      ) : (
        <span>{t('queryInput.hint')}</span>
      )}
    </div>
  )
  return (
    <Popover
      open={expanded}
      onOpenChange={(next) => {
        if (!next) setOpen(false)
      }}
    >
      {/* The list is placed against the field and its status line, or against
          the expanded editor while it is open. */}
      <PopoverAnchor virtualRef={listAnchor} />
      <div ref={anchorRef} className={cn('min-w-0', !quietStatus && 'space-y-1', className)}>
        <div className="relative">
          {multiline ? (
            <HighlightedTextarea
              textareaRef={ref}
              rows={3}
              className={cn('font-mono text-sm', inputClassName)}
              {...shared}
            />
          ) : big ? (
            <div data-slot="query-editor-expanded">
              <HighlightedTextarea
                textareaRef={ref}
                style={{ height: phase === 'open' ? openH : fieldH, maxHeight: maxH }}
                className={cn(
                  'min-h-0 resize-none py-1.5 font-mono',
                  inputClassName,
                  FIELD_CONTROLS_ROOM,
                  animating &&
                    'transition-[height] duration-200 ease-out motion-reduce:transition-none'
                )}
                {...shared}
              />
            </div>
          ) : (
            <Input
              ref={ref}
              className={cn(
                'font-mono',
                inputClassName,
                // Room for the field's own controls and the host's.
                inline && FIELD_CONTROLS_ROOM
              )}
              {...shared}
            />
          )}
          {/* The icon, the host's end controls and the field's own sit on the
              first line, the same in one line and expanded. */}
          <div className="pointer-events-none absolute inset-x-0 top-0 h-control-field max-md:h-control-touch [&>*]:pointer-events-auto">
            {adornments}
            {inline && (
              <Popover open={helpOpen} onOpenChange={setHelpOpen}>
                <PopoverAnchor asChild>
                  <div
                    ref={controlsRef}
                    data-slot="query-field-controls"
                    className={cn(
                      // Just before the host's end controls (a list search field's switch).
                      'absolute end-[calc(var(--list-search-end,0.5rem)-0.125rem)] top-1/2 z-50 flex -translate-y-1/2 items-center gap-0.5'
                    )}
                  >
                    {/* Help and expand: in the field from 768 px, and in the
                      expanded editor's header; on a phone's one-line field
                      they sit behind one overflow, so the text keeps its room. */}
                    <PopoverTrigger asChild>
                      <FieldIconButton
                        label={t('queryInput.help.open')}
                        className={big ? undefined : 'hidden md:flex'}
                      >
                        <CircleHelp className="size-4 md:size-3.5" aria-hidden />
                      </FieldIconButton>
                    </PopoverTrigger>
                    <FieldIconButton
                      label={t(big ? 'queryInput.collapse' : 'queryInput.expand')}
                      pressed={big}
                      className={big ? undefined : 'hidden md:flex'}
                      onClick={() => setBig(!big)}
                    >
                      {big ? (
                        <Minimize2 className="size-4 md:size-3.5" aria-hidden />
                      ) : (
                        <Maximize2 className="size-4 md:size-3.5" aria-hidden />
                      )}
                    </FieldIconButton>
                    {!big && (
                      <span className="contents md:hidden">
                        <ActionMenu
                          title={t('queryInput.mode.label')}
                          label={t('queryInput.more')}
                          items={[
                            {
                              id: 'help',
                              label: t('queryInput.help.open'),
                              icon: CircleHelp,
                              // After the menu has given the focus back.
                              onSelect: () => setTimeout(() => setHelpOpen(true), 0),
                            },
                            {
                              id: 'expand',
                              label: t('queryInput.expand'),
                              icon: Maximize2,
                              onSelect: () => setBig(true),
                            },
                          ]}
                          trigger={
                            <FieldIconButton label={t('queryInput.more')} keepFocus={false}>
                              <MoreHorizontal className="size-4" aria-hidden />
                            </FieldIconButton>
                          }
                        />
                      </span>
                    )}
                    <FieldIconButton
                      label={t('queryInput.run')}
                      slot="query-apply"
                      disabled={disabled || !dirty || checking}
                      emphasis={dirty}
                      shortcut="Enter"
                      onClick={submit}
                    >
                      <Play className="size-4 md:size-3.5" aria-hidden />
                    </FieldIconButton>
                  </div>
                </PopoverAnchor>
                <PopoverContent
                  className="w-[min(24rem,calc(100vw-2rem))] space-y-3 text-xs"
                  data-slot="query-help"
                  // Opened from the phone's overflow: the focus coming back to
                  // the field's controls does not close it.
                  onInteractOutside={(e) => {
                    if (e.target instanceof Node && controlsRef.current?.contains(e.target))
                      e.preventDefault()
                  }}
                >
                  <QuerySyntaxHelp entity={entity} />
                </PopoverContent>
              </Popover>
            )}
          </div>
        </div>
        {statusHost ? createPortal(statusLine, statusHost) : statusLine}
      </div>
      <PopoverContent
        asChild
        side="bottom"
        hideWhenDetached
        className={cn(SUGGESTION_LIST_CLASSES, !inOverlay && SUGGESTION_LIST_PHONE_CLASSES)}
        // The caret stays in the field: the list never takes focus.
        onOpenAutoFocus={(e) => e.preventDefault()}
        onCloseAutoFocus={(e) => e.preventDefault()}
        // Clicking in the field moves the caret; it does not close the list.
        onInteractOutside={(e) => {
          if (e.target instanceof Node && anchorRef.current?.contains(e.target)) e.preventDefault()
        }}
      >
        <SuggestionList
          id={listId}
          entity={entity}
          options={options}
          active={active}
          onPick={accept}
        />
      </PopoverContent>
    </Popover>
  )
}

/**
 * A text area whose text is coloured by kind (fields, operators, keywords,
 * values): the coloured copy sits behind a text area with transparent text
 * and the same box, so the caret, selection and editing stay native. The
 * copy is React text, never markup, and is hidden from assistive technology.
 * Lines break at spaces only, never inside a condition (`state=open`): a
 * condition longer than the line scrolls sideways, the copy with it.
 */
function HighlightedTextarea({
  textareaRef,
  className,
  value,
  ...props
}: React.ComponentProps<'textarea'> & {
  textareaRef: React.Ref<HTMLTextAreaElement>
  value: string
}) {
  const back = useRef<HTMLDivElement>(null)
  const tokens = useMemo(() => queryTokens(value), [value])
  const box =
    'rounded-md border px-3 py-2 text-base break-normal whitespace-pre-wrap md:text-sm [scrollbar-gutter:stable]'
  return (
    <div className="relative">
      <div
        ref={back}
        aria-hidden
        data-slot="query-highlight"
        className={cn(
          box,
          className,
          'dark:bg-input/30 pointer-events-none absolute inset-0 max-h-none min-h-0 resize-none overflow-hidden border-transparent'
        )}
      >
        {tokens.map((tok, i) => (
          <span key={i} className={TOKEN_CLASSES[tok.type]}>
            {tok.value}
          </span>
        ))}
        {/* A trailing newline keeps the last empty line's height. */}
        {'\n'}
      </div>
      <Textarea
        ref={textareaRef}
        value={value}
        className={cn(
          box,
          className,
          'caret-foreground relative bg-transparent text-transparent dark:bg-transparent'
        )}
        onScroll={(e) => {
          if (!back.current) return
          back.current.scrollTop = e.currentTarget.scrollTop
          back.current.scrollLeft = e.currentTarget.scrollLeft
        }}
        {...props}
      />
    </div>
  )
}

/** A touch screen without a mouse: the keyboard is not opened for the person. */
function coarsePointer(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.('(pointer: coarse)').matches
}

/**
 * An icon button inside the field (help, expand, run, more): 28 px on a phone
 * (in a 36 px field), 24 px from 768 px; labelled, with a tooltip for a
 * pointer (`title`). It passes the props of a trigger (`asChild`) through.
 */
const FieldIconButton = forwardRef<
  HTMLButtonElement,
  Omit<React.ComponentProps<'button'>, 'children'> & {
    label: string
    pressed?: boolean
    emphasis?: boolean
    slot?: string
    shortcut?: string
    /** Keeps the caret in the field on a click (not for a menu trigger). */
    keepFocus?: boolean
    children: ReactNode
  }
>(function FieldIconButton(
  { label, pressed, emphasis, slot, shortcut, keepFocus = true, className, children, ...props },
  ref
) {
  return (
    <button
      ref={ref}
      type="button"
      data-slot={slot}
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      aria-keyshortcuts={shortcut}
      {...props}
      onMouseDown={(e) => {
        // The caret stays in the field.
        if (keepFocus) e.preventDefault()
        props.onMouseDown?.(e)
      }}
      className={cn(
        'text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-ring flex size-7 items-center justify-center rounded-sm focus-visible:ring-2 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50 md:size-6',
        emphasis &&
          'bg-primary text-primary-foreground hover:bg-primary/90 hover:text-primary-foreground',
        className
      )}
    >
      {children}
    </button>
  )
})

/**
 * The query syntax at hand: how a condition is written, the operators, the
 * words that join conditions, examples, and the caller's own fields with
 * their operators, from the schema already read for completion.
 */
function QuerySyntaxHelp({ entity }: { entity: QueryEntity }) {
  const { t } = useTranslation()
  const { data: schema } = useQuerySchema(entity)
  const fields = schema?.fields ?? []
  return (
    <>
      <p className="text-card-title">{t('queryInput.help.title')}</p>
      <ul className="text-muted-foreground list-disc space-y-1 ps-4">
        <li>{t('queryInput.help.condition')}</li>
        <li>{t('queryInput.help.operators')}</li>
        <li>{t('queryInput.help.join')}</li>
        <li>{t('queryInput.help.quote')}</li>
        <li>{t('queryInput.help.keys')}</li>
      </ul>
      <div className="space-y-1">
        <p className="font-medium">{t('queryInput.help.examples')}</p>
        <p className="font-mono break-all" dir="ltr">
          {t(`queryInput.help.example.${entity}`)}
        </p>
      </div>
      {fields.length > 0 && (
        <div className="space-y-1">
          <p className="font-medium">{t('queryInput.help.fields')}</p>
          <ul className="max-h-48 space-y-0.5 overflow-y-auto" dir="ltr">
            {fields.map((f) => (
              <li key={f.path} className="flex gap-3">
                <span className="font-mono">{f.path}</span>
                <span className="text-muted-foreground font-mono">
                  {shortOperators(f).join(' ')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}

/** A quote or parenthesis that does not pair up, found while typing. */
function LocalProblemLine({
  problem,
  text,
  strong,
  row,
}: {
  problem: LocalProblem
  text: string
  strong: boolean
  /** One line of a fixed height: the text is cut, in full in its title. */
  row?: boolean
}) {
  const { t } = useTranslation()
  const column = [...text.slice(0, problem.start)].length + 1
  const message = `${t(`queryInput.local.${problem.code}`)} ${t('queryInput.atColumn', undefined, { column })}`
  return (
    <span
      className={cn(strong && 'text-destructive', row && 'min-w-0 truncate')}
      title={row ? message : undefined}
    >
      {message}
    </span>
  )
}

/** The first problem, in the person's language, with its fixes as buttons. */
function ProblemLine({
  problem,
  onFix,
  row,
}: {
  problem: QueryProblem
  onFix: (fix: string) => void
  /**
   * One line of a fixed height (a list toolbar's status row): the text is
   * cut, in full in its title; the fix buttons keep their size.
   */
  row?: boolean
}) {
  const { t } = useTranslation()
  const known = KNOWN_CODES.has(problem.code)
  const fixes = FIXABLE.has(problem.code) ? (problem.suggestions ?? []).slice(0, 3) : []
  const message =
    (known ? t(`queryInput.problem.${problem.code}`) : t('queryInput.problem.invalid')) +
    (DETAILED.has(problem.code) && problem.message ? ` (${problem.message})` : '') +
    (problem.column > 0
      ? ` ${t('queryInput.atColumn', undefined, { column: problem.column })}`
      : '') +
    (problem.code === 'operator_not_allowed' && problem.suggestions?.length
      ? ' ' + t('queryInput.allowedOperators', undefined, { ops: problem.suggestions.join(' ') })
      : '')
  return (
    <span
      data-slot="query-problem"
      className={cn(
        'text-destructive flex items-center gap-x-2',
        row ? 'min-w-0 flex-nowrap' : 'flex-wrap gap-y-1'
      )}
    >
      <span className={row ? 'min-w-0 truncate' : undefined} title={row ? message : undefined}>
        {message}
      </span>
      {fixes.length > 0 && (
        <span className={row ? 'shrink-0' : undefined}>{t('queryInput.didYouMean')}</span>
      )}
      {fixes.map((f) => (
        <Button
          key={f}
          type="button"
          variant="outline"
          size="sm"
          className="h-6 shrink-0 px-2 font-mono text-xs"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => onFix(f)}
        >
          {f}
        </Button>
      ))}
    </span>
  )
}

const KNOWN_CODES = new Set([
  'syntax',
  'unknown_field',
  'operator_not_allowed',
  'bad_value',
  'unknown_value',
  'pattern_not_allowed',
  'wrong_entity',
  'pipeline_not_allowed',
  'too_complex',
  'not_on_list',
])

// Problems whose server message (English, no values from the query) adds
// the specifics: what was expected.
const DETAILED = new Set(['syntax', 'bad_value'])

// Problems whose suggestions replace the problem's text (a field or a value).
const FIXABLE = new Set(['unknown_field', 'unknown_value'])
