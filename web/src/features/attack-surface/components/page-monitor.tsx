'use client'

/**
 * Attack surface › Page changes (RFC-138): watched pages and scripts of the
 * organization's web services, what changed on them, and URLs worth watching.
 * JS-only mode (default) follows the scripts a page loads; full page also
 * follows its visible text. A sensor fetches each URL on the watch's cadence
 * through the same scope gates as every active check; the platform compares
 * the fetches. Values from the pages are shown as plain text only.
 */

import { useMemo, useState } from 'react'
import {
  ChevronDown,
  ChevronRight,
  FileSearch,
  Loader2,
  Plus,
  Settings2,
  Trash2,
} from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import {
  EmptyState,
  ErrorState,
  FilterSelect,
  RelativeTime,
  SeverityBadge,
} from '@/features/shared'
import { StatusChip } from '@/features/shared/components/status-chip'
import { useUrlFilter } from '@/hooks/use-url-param'
import { getErrorMessage } from '@/lib/api/error-handler'
import { toSeverity } from './easm-overview'
import { PageChangeSheet, Untrusted } from './page-change-sheet'
import {
  createPageWatch,
  deletePageWatch,
  updatePageWatch,
  usePageChanges,
  usePageSuggestions,
  usePageWatches,
  type PageChange,
  type PageChangeSeverity,
  type PageSuggestion,
  type PageWatch,
  type PageWatchMode,
} from '../hooks/use-page-monitor'

const SEVERITIES: PageChangeSeverity[] = ['low', 'medium', 'high']
const CADENCE_MIN = 6
const CADENCE_MAX = 168
const cadenceValid = (n: number) => Number.isInteger(n) && n >= CADENCE_MIN && n <= CADENCE_MAX

function useModeLabel() {
  const { t } = useTranslation()
  return (m: PageWatchMode) =>
    m === 'full'
      ? t('pageMonitor.mode.full', 'Full page')
      : t('pageMonitor.mode.js', 'Scripts only')
}

/** The change's parts as short phrases ("1 new third-party host"). */
function useSummaryParts() {
  const { t } = useTranslation()
  return (c: PageChange): string[] => {
    const s = c.summary
    const out: string[] = []
    if (s.new_third_party_hosts > 0)
      out.push(
        t('pageMonitor.summary.newHosts', '{count} new third-party host(s)', {
          count: s.new_third_party_hosts,
        })
      )
    if (s.scripts_added > 0)
      out.push(
        t('pageMonitor.summary.scriptsAdded', '{count} script(s) added', { count: s.scripts_added })
      )
    if (s.scripts_removed > 0)
      out.push(
        t('pageMonitor.summary.scriptsRemoved', '{count} script(s) removed', {
          count: s.scripts_removed,
        })
      )
    if (s.content_changed) out.push(t('pageMonitor.summary.content', 'Content changed'))
    if (s.urls_added > 0)
      out.push(
        t('pageMonitor.summary.urlsAdded', '{count} new URL(s) in the script', {
          count: s.urls_added,
        })
      )
    if (s.lines_added + s.lines_removed > 0)
      out.push(
        t('pageMonitor.summary.lines', '{added} line(s) added, {removed} removed', {
          added: s.lines_added,
          removed: s.lines_removed,
        })
      )
    return out
  }
}

function RowsSkeleton() {
  return (
    <div className="space-y-3" aria-hidden>
      {Array.from({ length: 3 }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  )
}

function ChangesSection({ onOpen }: { onOpen: (id: string) => void }) {
  const { t } = useTranslation()
  const parts = useSummaryParts()
  const [sevParam, setSevParam] = useUrlFilter('severity', '')
  const [mutedParam, setMutedParam] = useUrlFilter('muted', '')
  const minSeverity = SEVERITIES.includes(sevParam as PageChangeSeverity)
    ? (sevParam as PageChangeSeverity)
    : ''
  const muted = mutedParam === 'true'
  const { changes, total, error, isLoading, mutate, hasMore, loadingMore, loadMore } =
    usePageChanges({ minSeverity, muted })
  const sevLabel = (s: PageChangeSeverity) => {
    switch (s) {
      case 'high':
        return t('pageMonitor.filter.high', 'High')
      case 'medium':
        return t('pageMonitor.filter.medium', 'Medium and higher')
      default:
        return t('pageMonitor.filter.low', 'Low and higher')
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('pageMonitor.changes.title', 'Changes')}</CardTitle>
        <CardDescription>
          {t(
            'pageMonitor.changes.description',
            'What changed on your watched pages and scripts, newest first. A script from a new third-party host is also raised as an exposure.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <FilterSelect
            label={t('pageMonitor.filter.severity', 'Severity')}
            value={minSeverity}
            options={SEVERITIES.map((s) => ({ value: s, label: sevLabel(s) }))}
            onChange={(v) => setSevParam(v)}
          />
          <div className="flex items-center gap-2">
            <Switch
              id="page-changes-muted"
              checked={muted}
              onCheckedChange={(on) => setMutedParam(on ? 'true' : '')}
            />
            <Label htmlFor="page-changes-muted" className="font-normal">
              {t('pageMonitor.filter.muted', 'Show muted changes')}
            </Label>
          </div>
        </div>
        {error ? (
          <ErrorState
            title={t('pageMonitor.changes.what', 'page changes')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <RowsSkeleton />
        ) : changes.length === 0 ? (
          <EmptyState
            card={false}
            icon={FileSearch}
            title={t('pageMonitor.changes.emptyTitle', 'No changes yet')}
            description={t(
              'pageMonitor.changes.empty',
              'The first fetch of a URL is its baseline. Changes appear here from the next fetch on.'
            )}
          />
        ) : (
          <>
            <ul className="divide-y" data-testid="page-changes">
              {changes.map((c) => (
                <li key={c.id}>
                  <button
                    type="button"
                    className="flex w-full flex-wrap items-start gap-3 py-3 text-start hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    onClick={() => onOpen(c.id)}
                    aria-label={t('pageMonitor.changes.open', 'Open the change of {url}', {
                      url: c.url,
                    })}
                  >
                    <SeverityBadge severity={toSeverity(c.severity)} />
                    <span className="min-w-0 flex-1 space-y-1">
                      <Untrusted value={c.url} className="block text-sm" />
                      {c.parent_url && (
                        <span className="flex flex-wrap gap-1 text-xs text-muted-foreground">
                          {t('pageMonitor.loadedBy', 'Loaded by')}
                          <Untrusted value={c.parent_url} />
                        </span>
                      )}
                      <span className="flex flex-wrap gap-2">
                        {parts(c).map((p) => (
                          <Badge key={p} variant="outline" className="font-normal">
                            {p}
                          </Badge>
                        ))}
                        {c.muted && (
                          <Badge variant="secondary" className="font-normal">
                            {t('pageMonitor.muted', 'Muted')}
                          </Badge>
                        )}
                      </span>
                    </span>
                    <span className="text-xs text-muted-foreground">
                      <RelativeTime date={c.detected_at} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
              <span>
                {t('pageMonitor.changes.count', '{shown} of {total}', {
                  shown: changes.length,
                  total,
                })}
              </span>
              {hasMore && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={loadingMore}
                  onClick={() => void loadMore()}
                >
                  {loadingMore && <Loader2 className="me-1.5 h-4 w-4 animate-spin" aria-hidden />}
                  {t('pageMonitor.changes.more', 'Show more')}
                </Button>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function WatchSettings({ watch, onSaved }: { watch: PageWatch; onSaved: () => void }) {
  const { t } = useTranslation()
  const modeLabel = useModeLabel()
  const [mode, setMode] = useState<PageWatchMode>(watch.mode)
  const [cadence, setCadence] = useState(watch.cadence_hours)
  const [patterns, setPatterns] = useState(watch.ignore_patterns.join('\n'))
  const [busy, setBusy] = useState(false)
  const id = `watch-${watch.id}`
  const save = async () => {
    setBusy(true)
    try {
      await updatePageWatch(watch.id, {
        mode,
        cadence_hours: cadence,
        ignore_patterns: patterns
          .split('\n')
          .map((p) => p.trim())
          .filter(Boolean),
      })
      toast.success(t('pageMonitor.saved', 'Watch saved'))
      onSaved()
    } catch (e) {
      toast.error(getErrorMessage(e, t('pageMonitor.saveFailed', 'Could not save the watch')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-3 rounded-md border p-3">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">
          {t('pageMonitor.mode.label', 'What to follow')}
        </legend>
        <RadioGroup
          value={mode}
          onValueChange={(v) => setMode(v as PageWatchMode)}
          className="flex flex-wrap gap-4"
        >
          {(['js', 'full'] as PageWatchMode[]).map((m) => (
            <div key={m} className="flex items-center gap-2">
              <RadioGroupItem value={m} id={`${id}-mode-${m}`} />
              <Label htmlFor={`${id}-mode-${m}`} className="font-normal">
                {modeLabel(m)}
              </Label>
            </div>
          ))}
        </RadioGroup>
      </fieldset>
      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor={`${id}-cadence`} className="font-normal">
          {t('pageMonitor.cadence', 'Check every (hours, 6 to 168)')}
        </Label>
        <Input
          id={`${id}-cadence`}
          type="number"
          min={CADENCE_MIN}
          max={CADENCE_MAX}
          className="w-24"
          value={cadence || ''}
          aria-invalid={!cadenceValid(cadence)}
          onChange={(e) => setCadence(Number(e.target.value))}
        />
      </div>
      <div className="space-y-1">
        <Label htmlFor={`${id}-ignore`} className="font-normal">
          {t('pageMonitor.ignore', 'Ignore patterns (one regular expression per line, at most 10)')}
        </Label>
        <Textarea
          id={`${id}-ignore`}
          rows={3}
          className="font-mono text-xs"
          value={patterns}
          onChange={(e) => setPatterns(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          {t(
            'pageMonitor.ignoreHint',
            'A script source, a URL found in a script or a text line that matches is left out. Saving clears the muted mark.'
          )}
        </p>
      </div>
      <Button size="sm" disabled={busy || !cadenceValid(cadence)} onClick={() => void save()}>
        {t('pageMonitor.save', 'Save')}
      </Button>
    </div>
  )
}

function WatchRow({
  watch,
  scripts,
  canWrite,
  onChanged,
  onRemove,
}: {
  watch: PageWatch
  scripts: PageWatch[]
  canWrite: boolean
  onChanged: () => void
  onRemove: (w: PageWatch) => void
}) {
  const { t } = useTranslation()
  const modeLabel = useModeLabel()
  const [editing, setEditing] = useState(false)
  const [showScripts, setShowScripts] = useState(false)
  const [busy, setBusy] = useState(false)
  const toggle = async (on: boolean) => {
    setBusy(true)
    try {
      await updatePageWatch(watch.id, { enabled: on })
      onChanged()
    } catch (e) {
      toast.error(getErrorMessage(e, t('pageMonitor.saveFailed', 'Could not save the watch')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <li className="space-y-2 py-3" data-testid="page-watch">
      <div className="flex flex-wrap items-center gap-2">
        <Untrusted value={watch.url} className="min-w-0 flex-1 text-sm" />
        <span className="flex items-center gap-1">
          {canWrite && (
            <Switch
              checked={watch.enabled}
              disabled={busy}
              aria-label={t('pageMonitor.enabled', 'Watch {url}', { url: watch.url })}
              onCheckedChange={(on) => void toggle(on)}
            />
          )}
          {canWrite && (
            <Button
              size="sm"
              variant="ghost"
              aria-label={t('pageMonitor.edit', 'Settings of {url}', { url: watch.url })}
              aria-expanded={editing}
              onClick={() => setEditing(!editing)}
            >
              <Settings2 className="h-4 w-4" aria-hidden />
            </Button>
          )}
          {canWrite && (
            <Button
              size="sm"
              variant="ghost"
              aria-label={t('pageMonitor.remove', 'Stop watching {url}', { url: watch.url })}
              onClick={() => onRemove(watch)}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
            </Button>
          )}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <StatusChip
          domain="webWatch"
          value={watch.enabled ? watch.state : 'off'}
          title={watch.last_error}
        />
        <Badge variant="outline" className="font-normal">
          {modeLabel(watch.mode)}
        </Badge>
        {watch.dynamic && (
          <Badge
            variant="secondary"
            className="font-normal"
            title={t(
              'pageMonitor.dynamicHint',
              'It changed on every recent check; its changes are muted until you edit the watch.'
            )}
          >
            {t('pageMonitor.dynamic', 'Changes on every check')}
          </Badge>
        )}
        <span>
          {watch.last_fetched_at ? (
            <>
              {t('pageMonitor.checked', 'Checked')} <RelativeTime date={watch.last_fetched_at} />
            </>
          ) : (
            t('pageMonitor.notChecked', 'Not checked yet')
          )}
        </span>
        <span>{t('pageMonitor.changeCount', '{count} change(s)', { count: watch.changes })}</span>
        {watch.state !== 'ok' && watch.last_error && <span>{watch.last_error}</span>}
      </div>
      {scripts.length > 0 && (
        <div>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-xs"
            aria-expanded={showScripts}
            onClick={() => setShowScripts(!showScripts)}
          >
            {showScripts ? (
              <ChevronDown className="me-1 h-3 w-3" aria-hidden />
            ) : (
              <ChevronRight className="me-1 h-3 w-3" aria-hidden />
            )}
            {t('pageMonitor.scriptsWatched', '{count} script(s) of this page watched with it', {
              count: scripts.length,
            })}
          </Button>
          {showScripts && (
            <ul className="ms-6 space-y-1" data-testid="page-watch-scripts">
              {scripts.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center gap-2 text-xs">
                  <Untrusted value={s.url} />
                  <StatusChip domain="webWatch" value={s.state} />
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {editing && (
        <WatchSettings
          watch={watch}
          onSaved={() => {
            setEditing(false)
            onChanged()
          }}
        />
      )}
    </li>
  )
}

function AddWatch({ onAdded }: { onAdded: () => void }) {
  const { t } = useTranslation()
  const modeLabel = useModeLabel()
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState<PageWatchMode>('js')
  const [busy, setBusy] = useState(false)
  const add = async () => {
    setBusy(true)
    try {
      await createPageWatch({ url: url.trim(), mode, source: 'manual' })
      toast.success(t('pageMonitor.added', 'Watching the URL'))
      setUrl('')
      onAdded()
    } catch (e) {
      toast.error(getErrorMessage(e, t('pageMonitor.addFailed', 'Could not watch the URL')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form
      className="flex flex-col gap-2 sm:flex-row sm:items-end"
      onSubmit={(e) => {
        e.preventDefault()
        if (url.trim()) void add()
      }}
    >
      <div className="min-w-0 flex-1 space-y-1">
        <Label htmlFor="page-watch-url">
          {t('pageMonitor.url', 'URL of one of your web services')}
        </Label>
        <Input
          id="page-watch-url"
          type="url"
          inputMode="url"
          placeholder="https://app.example.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
      </div>
      <div className="space-y-1">
        <Label htmlFor="page-watch-mode">{t('pageMonitor.mode.label', 'What to follow')}</Label>
        <Select value={mode} onValueChange={(v) => setMode(v as PageWatchMode)}>
          <SelectTrigger id="page-watch-mode" className="w-full sm:w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="js">{modeLabel('js')}</SelectItem>
            <SelectItem value="full">{modeLabel('full')}</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <Button type="submit" disabled={busy || !url.trim()}>
        {busy ? (
          <Loader2 className="me-1.5 h-4 w-4 animate-spin" aria-hidden />
        ) : (
          <Plus className="me-1.5 h-4 w-4" aria-hidden />
        )}
        {t('pageMonitor.add', 'Watch')}
      </Button>
    </form>
  )
}

function SuggestionsSection({
  canWrite,
  onAdded,
  open,
}: {
  canWrite: boolean
  onAdded: () => void
  open: boolean
}) {
  const { t } = useTranslation()
  const [asked, setAsked] = useState(false)
  // Open by itself while nothing is watched; otherwise on request.
  const shown = asked || open
  const { suggestions, isLoading, error, mutate } = usePageSuggestions(shown)
  const [busy, setBusy] = useState<string | null>(null)
  const reason = (r: PageSuggestion['reason']) => {
    switch (r) {
      case 'root':
        return t('pageMonitor.reason.root', 'Home page')
      case 'login':
        return t('pageMonitor.reason.login', 'Sign-in page')
      case 'admin':
        return t('pageMonitor.reason.admin', 'Admin page')
      default:
        return t('pageMonitor.reason.script', 'Script')
    }
  }
  const watch = async (s: PageSuggestion) => {
    setBusy(s.url)
    try {
      await createPageWatch({ url: s.url, mode: s.mode, source: 'suggested' })
      toast.success(t('pageMonitor.added', 'Watching the URL'))
      void mutate()
      onAdded()
    } catch (e) {
      toast.error(getErrorMessage(e, t('pageMonitor.addFailed', 'Could not watch the URL')))
    } finally {
      setBusy(null)
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('pageMonitor.suggestions.title', 'Suggested URLs')}</CardTitle>
        <CardDescription>
          {t(
            'pageMonitor.suggestions.description',
            'Home, sign-in and admin pages and scripts of your web services that nobody watches yet.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!shown ? (
          <Button variant="outline" size="sm" onClick={() => setAsked(true)}>
            {t('pageMonitor.suggestions.show', 'Show suggestions')}
          </Button>
        ) : error ? (
          <ErrorState
            title={t('pageMonitor.suggestions.what', 'suggested URLs')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <RowsSkeleton />
        ) : suggestions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t(
              'pageMonitor.suggestions.empty',
              'No suggestions: every known page is watched, or no web service was found yet.'
            )}
          </p>
        ) : (
          <ul className="divide-y" data-testid="page-suggestions">
            {suggestions.map((s) => (
              <li key={s.url} className="flex flex-wrap items-center gap-2 py-2">
                <Untrusted value={s.url} className="min-w-0 flex-1 text-sm" />
                <Badge variant="outline" className="font-normal">
                  {reason(s.reason)}
                </Badge>
                {canWrite && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy !== null}
                    onClick={() => void watch(s)}
                  >
                    {busy === s.url && (
                      <Loader2 className="me-1.5 h-4 w-4 animate-spin" aria-hidden />
                    )}
                    {t('pageMonitor.add', 'Watch')}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export function PageMonitor() {
  const { t } = useTranslation()
  const { watches, max, error, isLoading, mutate, canWrite } = usePageWatches()
  const [openChange, setOpenChange] = useState<string | null>(null)
  const [removing, setRemoving] = useState<PageWatch | null>(null)
  const { pages, scriptsOf } = useMemo(() => {
    const byParent = new Map<string, PageWatch[]>()
    const top: PageWatch[] = []
    for (const w of watches) {
      if (w.parent_id) byParent.set(w.parent_id, [...(byParent.get(w.parent_id) ?? []), w])
      else top.push(w)
    }
    return { pages: top, scriptsOf: (id: string) => byParent.get(id) ?? [] }
  }, [watches])
  const waiting = watches.some((w) => w.enabled && w.state === 'waiting')

  const remove = async () => {
    if (!removing) return
    try {
      await deletePageWatch(removing.id)
      toast.success(t('pageMonitor.removed', 'No longer watching the URL'))
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, t('pageMonitor.removeFailed', 'Could not remove the watch')))
    } finally {
      setRemoving(null)
    }
  }

  return (
    <div className="space-y-6">
      {waiting && (
        <p
          role="status"
          className="rounded-md border bg-muted/40 px-3 py-2 text-sm"
          data-testid="page-monitor-waiting"
        >
          {t(
            'pageMonitor.waiting',
            'Checks start when a sensor that can fetch web content is available. Your watches are kept until then.'
          )}
        </p>
      )}
      <ChangesSection onOpen={setOpenChange} />
      <Card>
        <CardHeader>
          <CardTitle>{t('pageMonitor.watches.title', 'Watched pages')}</CardTitle>
          <CardDescription>
            {t(
              'pageMonitor.watches.description',
              'Each URL is fetched on its schedule through the same scope checks as every active scan. Scripts only follows what a page loads; full page also follows its text.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {canWrite && <AddWatch onAdded={() => void mutate()} />}
          {error ? (
            <ErrorState
              title={t('pageMonitor.watches.what', 'watched pages')}
              error={error}
              onRetry={() => void mutate()}
            />
          ) : isLoading ? (
            <RowsSkeleton />
          ) : pages.length === 0 ? (
            <EmptyState
              card={false}
              icon={FileSearch}
              title={t('pageMonitor.watches.emptyTitle', 'No watched pages')}
              description={t(
                'pageMonitor.watches.empty',
                'Watch a sign-in page or a home page to learn when it starts loading a new script.'
              )}
            />
          ) : (
            <>
              <ul className="divide-y" data-testid="page-watches">
                {pages.map((w) => (
                  <WatchRow
                    key={w.id}
                    watch={w}
                    scripts={scriptsOf(w.id)}
                    canWrite={canWrite}
                    onChanged={() => void mutate()}
                    onRemove={setRemoving}
                  />
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">
                {t('pageMonitor.watches.count', '{count} of {max} watches used', {
                  count: watches.length,
                  max,
                })}
              </p>
            </>
          )}
        </CardContent>
      </Card>
      <SuggestionsSection
        canWrite={canWrite}
        open={!isLoading && pages.length === 0}
        onAdded={() => void mutate()}
      />
      <PageChangeSheet changeId={openChange} onClose={() => setOpenChange(null)} />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={t('pageMonitor.removeTitle', 'Stop watching this URL?')}
        desc={t(
          'pageMonitor.removeBody',
          'Its scripts, stored snapshots and change history are deleted.'
        )}
        confirmText={t('pageMonitor.removeConfirm', 'Stop watching')}
        destructive
        handleConfirm={() => void remove()}
      />
    </div>
  )
}
