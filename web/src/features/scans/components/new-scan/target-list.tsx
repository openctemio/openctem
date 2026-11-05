'use client'

/**
 * The typed targets of a scan as a list, once there are more than a few
 * chips can show: each entry with its kind and the scope check's answer
 * (in scope and by which rule, or refused and why; entries that are not
 * valid targets with the reason), filtered to the ones that need attention,
 * searchable, each removable (and editable when not valid). Virtualised, so
 * a thousand entries stay fast. Scope is the server's answer (POST
 * /scope/check), never decided here. Design: research/418.
 */

import { useMemo, useState } from 'react'
import { AlertCircle, AlertTriangle, CheckCircle2, Loader2, Pencil, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ListSearch } from '@/features/shared/components/list-search'
import { Tabs, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { VirtualList } from '@/components/ui/virtual-list'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { scopeRefusalLabel, scopeRefusalMessage, type ApiScopeCheckResult } from '@/features/scope'
import { isRefusedKind, TARGET_KIND_LABELS, type ClassifiedTarget } from '../../lib/target-format'
import type { Translate } from '../../lib/translate'

const ROW = 52

export type TargetFilter = 'all' | 'attention'

interface TargetListProps {
  entries: readonly ClassifiedTarget[]
  /** The scope check's answer for a sent target. */
  resultFor?: (target: string) => ApiScopeCheckResult | undefined
  /** The check is on its way. */
  checking?: boolean
  /** The caller may run the check (scope:read); otherwise rows say "not checked". */
  checkAvailable?: boolean
  onRemove: (entry: ClassifiedTarget) => void
  onReplace: (entry: ClassifiedTarget, next: string) => void
}

export type RowState =
  | { kind: 'invalid'; text: string }
  | { kind: 'allowed'; text: string }
  | { kind: 'refused'; text: string; title?: string }
  | { kind: 'checking' }
  | { kind: 'unchecked' }

/**
 * A sent target's scope answer as a row state: in scope (and by which rule),
 * refused (and why), on its way, or not checked (no scope:read). Shared by
 * this list and the Targets step's groups.
 */
export function targetVerdict(
  t: Translate,
  r: ApiScopeCheckResult | undefined,
  opts: { checking?: boolean; checkAvailable?: boolean }
): RowState {
  if (r?.allowed) {
    return {
      kind: 'allowed',
      text: r.via?.pattern
        ? t('scans.targetList.inScopeVia', undefined, { rule: r.via.pattern })
        : t('scope.check.inScope', 'In scope'),
    }
  }
  if (r) {
    return {
      kind: 'refused',
      text: scopeRefusalLabel(t, r.code),
      title: scopeRefusalMessage(t, r.code, r.message),
    }
  }
  return (opts.checkAvailable ?? true) && opts.checking
    ? { kind: 'checking' }
    : { kind: 'unchecked' }
}

/** The words of a row state. */
export function verdictText(t: Translate, state: RowState): string {
  if (state.kind === 'checking') return t('scans.targetList.checking')
  if (state.kind === 'unchecked') return t('scans.targetList.unchecked')
  return state.text
}

export function TargetList({
  entries,
  resultFor,
  checking,
  checkAvailable = true,
  onRemove,
  onReplace,
}: TargetListProps) {
  const { t } = useTranslation()
  const [filter, setFilter] = useState<TargetFilter>('all')
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<string | null>(null)
  const [draft, setDraft] = useState('')

  const rows = useMemo(
    () =>
      entries.map((entry) => ({
        entry,
        state: isRefusedKind(entry.kind)
          ? ({
              kind: 'invalid',
              text: entry.reasonKey ? t(entry.reasonKey, entry.reason) : (entry.reason ?? ''),
            } as const)
          : targetVerdict(t, resultFor?.(entry.value), { checking, checkAvailable }),
      })),
    [entries, resultFor, checking, checkAvailable, t]
  )
  const attention = rows.filter((r) => r.state.kind === 'invalid' || r.state.kind === 'refused')
  const q = query.trim().toLowerCase()
  const shown = (filter === 'attention' ? attention : rows).filter(
    (r) => !q || r.entry.input.toLowerCase().includes(q) || r.entry.value.includes(q)
  )

  return (
    <div className="min-w-0 space-y-2" data-testid="target-list">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Tabs value={filter} onValueChange={(v) => setFilter(v as TargetFilter)}>
          <TabsList>
            <TabsTrigger value="all">
              {t('scans.targetList.all')}
              <TabsCount value={rows.length} />
            </TabsTrigger>
            <TabsTrigger value="attention" data-testid="target-list-attention">
              {t('scans.targetList.attention')}
              <TabsCount value={attention.length || null} />
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <ListSearch
          value={query}
          onChange={setQuery}
          placeholder={t('scans.targetList.search')}
          className="min-w-40"
        />
      </div>
      {shown.length === 0 ? (
        <p className="py-4 text-center text-sm text-muted-foreground">
          {filter === 'attention' && !q
            ? t('scans.targetList.noneNeedAttention')
            : t('scans.targetList.noMatch')}
        </p>
      ) : (
        <VirtualList
          items={shown}
          rowHeight={ROW}
          maxHeight={ROW * 7}
          label={t('scans.targetList.label')}
          getKey={(r, i) => `${r.entry.value}:${i}`}
          className="border"
          data-testid="target-list-rows"
          renderRow={({ entry, state }) =>
            editing === entry.input ? (
              <form
                className="flex h-full items-center gap-1.5 border-b px-2"
                onSubmit={(e) => {
                  e.preventDefault()
                  setEditing(null)
                  if (draft.trim() && draft.trim() !== entry.input) onReplace(entry, draft.trim())
                }}
              >
                <Input
                  autoFocus
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Escape') {
                      e.stopPropagation()
                      setEditing(null)
                    }
                  }}
                  aria-label={t('scans.paste.edit', undefined, { name: entry.input })}
                  className="h-9 min-w-0 flex-1 font-mono text-sm"
                  autoCapitalize="none"
                  spellCheck={false}
                />
                <Button type="submit" size="sm" className="h-9">
                  {t('scans.paste.save')}
                </Button>
              </form>
            ) : (
              <div
                className="flex h-full min-w-0 items-center gap-2 border-b px-2"
                data-state={state.kind}
              >
                <StateIcon state={state} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-sm" title={entry.input}>
                    {entry.input}
                  </span>
                  <span
                    className={cn(
                      'block truncate text-xs',
                      state.kind === 'invalid' ? 'text-destructive' : 'text-muted-foreground'
                    )}
                    title={state.kind === 'refused' ? state.title : undefined}
                  >
                    {isRefusedKind(entry.kind)
                      ? null
                      : `${t(`scans.kind.${entry.kind}`, TARGET_KIND_LABELS[entry.kind])}, `}
                    {verdictText(t, state)}
                  </span>
                </span>
                {isRefusedKind(entry.kind) && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-9 w-9 shrink-0 max-sm:h-11 max-sm:w-11"
                    onClick={() => {
                      setDraft(entry.input)
                      setEditing(entry.input)
                    }}
                    aria-label={t('scans.paste.edit', undefined, { name: entry.input })}
                  >
                    <Pencil className="h-4 w-4" aria-hidden />
                  </Button>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-9 w-9 shrink-0 max-sm:h-11 max-sm:w-11"
                  onClick={() => onRemove(entry)}
                  aria-label={t('scans.summary.remove', undefined, { name: entry.input })}
                >
                  <X className="h-4 w-4" aria-hidden />
                </Button>
              </div>
            )
          }
        />
      )}
    </div>
  )
}

export function StateIcon({ state }: { state: RowState }) {
  switch (state.kind) {
    case 'invalid':
      return <AlertCircle className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
    case 'refused':
      return <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden />
    case 'allowed':
      return <CheckCircle2 className="h-4 w-4 shrink-0 text-signal-text" aria-hidden />
    case 'checking':
      return <Loader2 className="h-4 w-4 shrink-0 animate-spin text-muted-foreground" aria-hidden />
    default:
      return <span className="h-4 w-4 shrink-0" aria-hidden />
  }
}
