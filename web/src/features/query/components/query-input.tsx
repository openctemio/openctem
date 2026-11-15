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

import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { CircleHelp, CornerDownLeft, Maximize2, Minimize2 } from 'lucide-react'
import { Popover, PopoverAnchor, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
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

/** Value lookup delay after the last key. */
export const VALUES_DELAY_MS = 300
/** Characters of a value typed before the server is asked for values (Ctrl+Space asks at once). */
export const VALUES_MIN_PREFIX = 2
const MAX_OPTIONS = 10

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
  onEscape,
}: QueryInputProps) {
  const { t, locale } = useTranslation()
  const ownId = useId()
  const inputId = id ?? `${ownId}-input`
  const listId = `${ownId}-list`
  const statusId = `${ownId}-status`
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null)
  const anchorRef = useRef<HTMLDivElement>(null)
  const bigRef = useRef<HTMLDivElement>(null)
  // The editor's first mount may take the focus (`autoFocus`); swapping the
  // one-line field and the expanded editor moves it by hand (setBig).
  const [swapped, setSwapped] = useState(false)
  const listAnchor = useMemo(
    () => ({
      current: {
        getBoundingClientRect: () =>
          (bigRef.current ?? anchorRef.current)?.getBoundingClientRect() ?? new DOMRect(),
      },
    }),
    []
  )
  const { data: schema } = useQuerySchema(entity, !disabled)
  const fields = useMemo(() => {
    const all = schema?.fields ?? []
    if (!preferFields?.length) return all
    const first = new Set(preferFields)
    return [...all.filter((f) => first.has(f.path)), ...all.filter((f) => !first.has(f.path))]
  }, [schema, preferFields])
  const scope = recentScope ?? entity

  const [caret, setCaret] = useState(0)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  // Ctrl+Space: values are asked for at once, whatever was typed.
  const [explicit, setExplicit] = useState(false)
  // The list field's expanded editor (several lines, over the content below)
  // and the text it opened with (Escape folds it back when unchanged).
  const [big, setBigState] = useState(false)
  const [bigFrom, setBigFrom] = useState('')
  const setBig = (on: boolean) => {
    const el = ref.current
    const from = el?.selectionStart ?? value.length
    const to = el?.selectionEnd ?? from
    setSwapped(true)
    // One line cannot hold a line break: each becomes a space, so the
    // conditions stay apart and the caret keeps its place.
    if (!on && /[\r\n]/.test(value)) onChange(value.replace(/[\r\n]/g, ' '))
    setBigState(on)
    setBigFrom(value)
    setOpen(false)
    requestAnimationFrame(() => {
      const next = ref.current
      // On a touch screen the keyboard opens only when the person taps the text.
      if (!next || coarsePointer()) return
      next.focus()
      next.setSelectionRange(from, to)
      setCaret(from)
    })
  }
  // The expanded editor fits the visible part of the screen (above a phone's
  // keyboard, inside a zoomed page), following the visual viewport.
  useEffect(() => {
    const vv = typeof window === 'undefined' ? null : window.visualViewport
    if (!big || !vv) return
    const fit = () => {
      const box = bigRef.current
      if (!box) return
      const status = box.lastElementChild?.getBoundingClientRect().height ?? 0
      const room = vv.offsetTop + vv.height - box.getBoundingClientRect().top - status - 16
      box.style.setProperty('--query-editor-room', `${Math.max(96, Math.floor(room))}px`)
    }
    fit()
    vv.addEventListener('resize', fit)
    vv.addEventListener('scroll', fit)
    window.addEventListener('scroll', fit, { passive: true })
    return () => {
      vv.removeEventListener('resize', fit)
      vv.removeEventListener('scroll', fit)
      window.removeEventListener('scroll', fit)
    }
  }, [big])
  // The server's answer to the text it was asked about on Apply.
  const [answer, setAnswer] = useState<{ text: string; result: ParseResult } | null>(null)
  // Apply refused before asking (quotes or parentheses do not pair up).
  const [refused, setRefused] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)
  const [failed, setFailed] = useState<string | null>(null)
  const [remote, setRemote] = useState<{ key: string; options: Completion[] } | null>(null)

  const ctx: CaretContext = useMemo(() => contextAt(value, caret), [value, caret])
  const field = useMemo(
    () => (ctx.kind === 'value' ? fields.find((f) => f.path === ctx.path) : undefined),
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
      return readRecent(scope)
        .slice(0, MAX_OPTIONS)
        .map((r) => ({ kind: 'recent' as const, label: r, insert: r }))
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
      if (listOpen && !e.ctrlKey && !e.metaKey) {
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
    autoFocus: autoFocus && !swapped,
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
  const statusLine = (
    <div
      id={statusId}
      aria-live="polite"
      className={cn(
        'text-muted-foreground min-h-5 text-xs',
        // A list field adds no space under itself until there is a problem.
        big ? 'px-3 pb-2' : quietStatus && (drawn ? 'mt-1' : 'sr-only')
      )}
    >
      {problem ? (
        <ProblemLine
          problem={problem}
          onFix={(fix) =>
            setText(applyFix(value, problem.start, problem.end, fix), problem.start + fix.length)
          }
        />
      ) : local ? (
        <LocalProblemLine problem={local} text={value} strong={localShown} />
      ) : checking ? (
        <span>{t('queryInput.checking')}</span>
      ) : failed === value ? (
        <span>{t('queryInput.unavailable')}</span>
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
            <>
              {/* Keeps the toolbar row one line high: the editor opens over
                    the content below, so no other control moves. */}
              <Input
                aria-hidden
                tabIndex={-1}
                readOnly
                value=""
                className={cn('invisible', inputClassName)}
              />
              <div
                ref={bigRef}
                data-slot="query-editor-expanded"
                className="bg-popover absolute inset-x-0 top-0 z-40 rounded-md shadow-md"
              >
                <HighlightedTextarea
                  textareaRef={ref}
                  rows={10}
                  className="max-h-[min(60vh,var(--query-editor-room,60vh))] min-h-[min(15rem,var(--query-editor-room,15rem))] resize-y pe-24 font-mono text-sm"
                  {...shared}
                />
                {statusLine}
              </div>
            </>
          ) : (
            <Input
              ref={ref}
              className={cn(
                'font-mono',
                inputClassName,
                // Room for the field's own controls and the host's.
                inline && 'pe-[calc(var(--list-search-end,0.5rem)+4.75rem)]'
              )}
              {...shared}
            />
          )}
          {!big && adornments}
          {inline && (
            <div
              data-slot="query-field-controls"
              className={cn(
                'absolute z-50 flex items-center gap-0.5',
                big
                  ? 'end-2 top-1.5'
                  : // Just before the host's end controls (a list search field's switch).
                    'end-[calc(var(--list-search-end,0.5rem)-0.125rem)] top-1/2 -translate-y-1/2'
              )}
            >
              <QuerySyntaxHelp entity={entity} />
              <FieldIconButton
                label={t(big ? 'queryInput.collapse' : 'queryInput.expand')}
                pressed={big}
                onClick={() => setBig(!big)}
              >
                {big ? (
                  <Minimize2 className="size-3.5" aria-hidden />
                ) : (
                  <Maximize2 className="size-3.5" aria-hidden />
                )}
              </FieldIconButton>
              <FieldIconButton
                label={t('queryInput.run')}
                slot="query-apply"
                disabled={disabled || !dirty || checking}
                emphasis={dirty}
                onClick={submit}
              >
                <CornerDownLeft className="size-3.5" aria-hidden />
              </FieldIconButton>
            </div>
          )}
        </div>
        {!big && statusLine}
      </div>
      <PopoverContent
        asChild
        side="bottom"
        hideWhenDetached
        className={SUGGESTION_LIST_CLASSES}
        // The caret stays in the field: the list never takes focus.
        onOpenAutoFocus={(e) => e.preventDefault()}
        onCloseAutoFocus={(e) => e.preventDefault()}
        // Clicking in the field moves the caret; it does not close the list.
        onInteractOutside={(e) => {
          if (e.target instanceof Node && anchorRef.current?.contains(e.target)) e.preventDefault()
        }}
      >
        <ul id={listId} role="listbox" aria-label={t('queryInput.suggestions')}>
          {options.map((o, i) => (
            <li
              key={`${o.kind}-${o.label}`}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              className={cn(
                'flex cursor-pointer items-center justify-between gap-3 rounded px-2 py-1 text-xs',
                i === active && 'bg-accent text-accent-foreground'
              )}
              onMouseDown={(e) => {
                e.preventDefault()
                accept(o)
              }}
            >
              <span className="truncate font-mono">{o.label}</span>
              <span className="text-muted-foreground shrink-0">
                {o.count !== undefined
                  ? formatCount(o.count, locale)
                  : t(`queryInput.kind.${o.kind}`)}
              </span>
            </li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  )
}

/**
 * A text area whose text is coloured by kind (fields, operators, keywords,
 * values): the coloured copy sits behind a text area with transparent text
 * and the same box, so the caret, selection and editing stay native. The
 * copy is React text, never markup, and is hidden from assistive technology.
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
  const box = 'rounded-md border px-3 py-2 text-base md:text-sm [scrollbar-gutter:stable]'
  return (
    <div className="relative">
      <div
        ref={back}
        aria-hidden
        data-slot="query-highlight"
        className={cn(
          box,
          className,
          'dark:bg-input/30 pointer-events-none absolute inset-0 max-h-none min-h-0 resize-none overflow-hidden border-transparent break-words whitespace-pre-wrap'
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
          if (back.current) back.current.scrollTop = e.currentTarget.scrollTop
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

/** An icon button inside the field (help, expand, run): 24 px, labelled. */
function FieldIconButton({
  label,
  onClick,
  disabled,
  pressed,
  emphasis,
  slot,
  children,
}: {
  label: string
  onClick: () => void
  disabled?: boolean
  pressed?: boolean
  emphasis?: boolean
  slot?: string
  children: ReactNode
}) {
  return (
    <button
      type="button"
      data-slot={slot}
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      disabled={disabled}
      // The caret stays in the field.
      onMouseDown={(e) => e.preventDefault()}
      onClick={onClick}
      className={cn(
        'text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-ring flex size-6 items-center justify-center rounded-sm focus-visible:ring-2 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50',
        emphasis &&
          'bg-primary text-primary-foreground hover:bg-primary/90 hover:text-primary-foreground'
      )}
    >
      {children}
    </button>
  )
}

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
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={t('queryInput.help.open')}
          title={t('queryInput.help.open')}
          className="text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-ring flex size-6 items-center justify-center rounded-sm focus-visible:ring-2 focus-visible:outline-none"
        >
          <CircleHelp className="size-3.5" aria-hidden />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-96 space-y-3 text-xs" data-slot="query-help">
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
            <ul className="space-y-0.5" dir="ltr">
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
      </PopoverContent>
    </Popover>
  )
}

/** A quote or parenthesis that does not pair up, found while typing. */
function LocalProblemLine({
  problem,
  text,
  strong,
}: {
  problem: LocalProblem
  text: string
  strong: boolean
}) {
  const { t } = useTranslation()
  const column = [...text.slice(0, problem.start)].length + 1
  return (
    <span className={cn(strong && 'text-destructive')}>
      {t(`queryInput.local.${problem.code}`)} {t('queryInput.atColumn', undefined, { column })}
    </span>
  )
}

/** The first problem, in the person's language, with its fixes as buttons. */
function ProblemLine({ problem, onFix }: { problem: QueryProblem; onFix: (fix: string) => void }) {
  const { t } = useTranslation()
  const known = KNOWN_CODES.has(problem.code)
  const fixes = FIXABLE.has(problem.code) ? (problem.suggestions ?? []).slice(0, 3) : []
  return (
    <span className="text-destructive flex flex-wrap items-center gap-x-2 gap-y-1">
      <span>
        {known ? t(`queryInput.problem.${problem.code}`) : t('queryInput.problem.invalid')}
        {DETAILED.has(problem.code) && problem.message ? ` (${problem.message})` : ''}
        {problem.column > 0
          ? ` ${t('queryInput.atColumn', undefined, { column: problem.column })}`
          : ''}
        {problem.code === 'operator_not_allowed' && problem.suggestions?.length
          ? ' ' +
            t('queryInput.allowedOperators', undefined, { ops: problem.suggestions.join(' ') })
          : ''}
      </span>
      {fixes.length > 0 && <span>{t('queryInput.didYouMean')}</span>}
      {fixes.map((f) => (
        <Button
          key={f}
          type="button"
          variant="outline"
          size="sm"
          className="h-6 px-2 font-mono text-xs"
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
