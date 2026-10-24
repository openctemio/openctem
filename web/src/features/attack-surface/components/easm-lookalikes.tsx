'use client'

/**
 * Attack surface › Lookalikes (RFC-083): passive monitoring of the
 * organization's root domains for registered lookalikes (typos, homoglyphs,
 * bit flips, hyphens, other TLDs). Checks are DNS lookups through the
 * platform resolver and Certificate Transparency only; no lookalike host is
 * contacted. Registered lookalikes are lookalike_domain exposures, triaged
 * here: ours or benign (accept), not a threat (false positive), taken down
 * (resolve).
 */

import { useState } from 'react'
import { Copy, Loader2, Plus, Settings2, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import {
  acceptExposure,
  markExposureFalsePositive,
  resolveExposure,
} from '@/features/exposures/hooks/use-exposures'
import { EmptyState, ErrorState, RelativeTime, SeverityBadge } from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import { toSeverity } from './easm-overview'
import type { LookalikeWatch } from '@/lib/api/generated'
import type { ExposureEvent } from '@/lib/api/exposure-types'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import {
  createLookalikeWatch,
  deleteLookalikeWatch,
  updateLookalikeWatch,
  useLookalikeExposures,
  useLookalikeWatches,
} from '../hooks/use-easm-lookalikes'
import { confirmName } from '@/lib/confirm-name'

/** Candidates one watch may check (the API's range). */
const MAX_CANDIDATES_MIN = 10
const MAX_CANDIDATES_MAX = 1000
const maxValid = (n: number) =>
  Number.isInteger(n) && n >= MAX_CANDIDATES_MIN && n <= MAX_CANDIDATES_MAX

type ReviewState = 'active' | 'accepted' | 'false_positive' | 'resolved'
const REVIEW_STATES: ReviewState[] = ['active', 'accepted', 'false_positive', 'resolved']

function useTechniqueLabel() {
  const { t } = useTranslation()
  return (tech: string) => {
    switch (tech) {
      case 'omission':
        return t('lookalikes.tech.omission', 'Missing letter')
      case 'repetition':
        return t('lookalikes.tech.repetition', 'Doubled letter')
      case 'transposition':
        return t('lookalikes.tech.transposition', 'Swapped letters')
      case 'replacement':
        return t('lookalikes.tech.replacement', 'Neighboring key')
      case 'insertion':
        return t('lookalikes.tech.insertion', 'Extra key')
      case 'hyphenation':
        return t('lookalikes.tech.hyphenation', 'Hyphen')
      case 'bitflip':
        return t('lookalikes.tech.bitflip', 'Bit flip')
      case 'homoglyph':
        return t('lookalikes.tech.homoglyph', 'Look-alike characters')
      case 'tld':
        return t('lookalikes.tech.tld', 'Other ending (TLD)')
      default:
        return tech
    }
  }
}

function WatchSettings({
  techniques,
  selected,
  onChange,
  max,
  onMax,
  idPrefix,
}: {
  techniques: string[]
  selected: string[]
  onChange: (next: string[]) => void
  max: number
  onMax: (n: number) => void
  idPrefix: string
}) {
  const { t } = useTranslation()
  const label = useTechniqueLabel()
  return (
    <div className="space-y-3">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">
          {t('lookalikes.techniques', 'Kinds of lookalikes (none selected: all)')}
        </legend>
        <div className="grid gap-2 sm:grid-cols-3">
          {techniques.map((tech) => {
            const id = `${idPrefix}-${tech}`
            return (
              <div key={tech} className="flex items-center gap-2">
                <Checkbox
                  id={id}
                  checked={selected.includes(tech)}
                  onCheckedChange={(on) =>
                    onChange(on ? [...selected, tech] : selected.filter((s) => s !== tech))
                  }
                />
                <Label htmlFor={id} className="font-normal">
                  {label(tech)}
                </Label>
              </div>
            )
          })}
        </div>
      </fieldset>
      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor={`${idPrefix}-max`} className="font-normal">
          {t('lookalikes.max', 'Candidates to check (10 to 1000)')}
        </Label>
        <Input
          id={`${idPrefix}-max`}
          type="number"
          min={10}
          max={1000}
          className="w-28"
          value={max || ''}
          aria-invalid={!maxValid(max)}
          aria-describedby={maxValid(max) ? undefined : `${idPrefix}-max-error`}
          onChange={(e) => onMax(Number(e.target.value))}
        />
        {!maxValid(max) && (
          <p id={`${idPrefix}-max-error`} className="text-xs text-destructive">
            {t('lookalikes.maxInvalid', 'Enter a whole number from 10 to 1000')}
          </p>
        )}
      </div>
    </div>
  )
}

function WatchRow({
  watch,
  techniques,
  canWrite,
  canDelete,
  onChanged,
  onRemove,
}: {
  watch: LookalikeWatch
  techniques: string[]
  canWrite: boolean
  canDelete: boolean
  onChanged: () => void
  onRemove: (w: LookalikeWatch) => void
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [selected, setSelected] = useState<string[]>(watch.techniques ?? [])
  const [max, setMax] = useState(watch.max_candidates ?? 300)
  const [busy, setBusy] = useState(false)

  const save = async (enabled: boolean, techs: string[], maxN: number) => {
    if (!watch.id) return
    setBusy(true)
    try {
      await updateLookalikeWatch(watch.id, { enabled, techniques: techs, max_candidates: maxN })
      toast.success(t('lookalikes.saved', 'Watch saved'))
      setEditing(false)
      onChanged()
    } catch (e) {
      toast.error(getErrorMessage(e, t('lookalikes.saveFailed', 'Could not save the watch')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="space-y-3 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-medium">{watch.domain}</span>
        <span className="text-xs text-muted-foreground">
          {t(
            'lookalikes.counts',
            '{registered} registered of {checked} checked ({candidates} candidates)',
            {
              registered: watch.registered ?? 0,
              checked: watch.checked ?? 0,
              candidates: watch.candidates ?? 0,
            }
          )}
        </span>
        <span className="ms-auto flex items-center gap-2">
          <Switch
            checked={!!watch.enabled}
            disabled={!canWrite || busy}
            aria-label={t('lookalikes.enabled', 'Monitor {domain}', { domain: watch.domain ?? '' })}
            onCheckedChange={(on) =>
              void save(on, watch.techniques ?? [], watch.max_candidates ?? 300)
            }
          />
          {canWrite && (
            <Button
              size="sm"
              variant="ghost"
              aria-label={t('lookalikes.edit', 'Settings of {domain}', {
                domain: watch.domain ?? '',
              })}
              onClick={() => {
                // Opening the form starts from what the watch has now, not from
                // the values it had when the row first rendered.
                if (!editing) {
                  setSelected(watch.techniques ?? [])
                  setMax(watch.max_candidates ?? 300)
                }
                setEditing(!editing)
              }}
            >
              <Settings2 className="h-4 w-4" aria-hidden />
            </Button>
          )}
          {canDelete && (
            <Button
              size="sm"
              variant="ghost"
              aria-label={t('lookalikes.remove', 'Stop watching {domain}', {
                domain: watch.domain ?? '',
              })}
              onClick={() => onRemove(watch)}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
            </Button>
          )}
        </span>
      </div>
      {editing && (
        <div className="space-y-3 rounded-md border p-3">
          <WatchSettings
            techniques={techniques}
            selected={selected}
            onChange={setSelected}
            max={max}
            onMax={setMax}
            idPrefix={`watch-${watch.id}`}
          />
          <Button
            size="sm"
            disabled={busy || !maxValid(max)}
            onClick={() => void save(!!watch.enabled, selected, max)}
          >
            {t('lookalikes.save', 'Save')}
          </Button>
        </div>
      )}
    </li>
  )
}

function ReviewRow({
  exposure,
  canTriage,
  onChanged,
}: {
  exposure: ExposureEvent
  canTriage: boolean
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const label = useTechniqueLabel()
  const [busy, setBusy] = useState(false)
  const d = (exposure.details ?? {}) as Record<string, unknown>
  const ascii = String(d.domain ?? exposure.title)
  const display = String(d.display ?? ascii)
  const act = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true)
    try {
      await fn()
      toast.success(done)
      onChanged()
    } catch (e) {
      toast.error(getErrorMessage(e, t('lookalikes.triageFailed', 'The change was not saved')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <li className="flex flex-wrap items-center gap-3 py-3">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="break-all font-medium">{display}</span>
          {display !== ascii && (
            // An IDN homoglyph reads like the real name: always show what it really is.
            <span className="break-all font-mono text-xs text-muted-foreground">{ascii}</span>
          )}
          <SeverityBadge severity={toSeverity(exposure.severity)} />
          {d.has_mx === true && (
            <Badge variant="outline">{t('lookalikes.mail', 'Receives mail')}</Badge>
          )}
          {d.has_a === true && (
            <Badge variant="outline">{t('lookalikes.web', 'Has addresses')}</Badge>
          )}
          {typeof d.ct_certificates === 'number' && d.ct_certificates > 0 && (
            <Badge variant="outline">
              {t('lookalikes.certs', '{count} certificates', { count: d.ct_certificates })}
            </Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          {t('lookalikes.of', 'Lookalike of {domain}', { domain: String(d.lookalike_of ?? '') })}
          {typeof d.technique === 'string' && ` · ${label(d.technique)}`} ·{' '}
          <RelativeTime date={exposure.first_seen_at} />
        </p>
      </div>
      {canTriage && exposure.state === 'active' && exposure.id && (
        <span className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() =>
              void act(
                () =>
                  acceptExposure(exposure.id, { reason: 'Owned by the organization or benign' }),
                t('lookalikes.accepted', 'Marked as ours or benign')
              )
            }
          >
            {t('lookalikes.accept', 'Ours or benign')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() =>
              void act(
                () => markExposureFalsePositive(exposure.id, { reason: 'Not a threat' }),
                t('lookalikes.dismissed', 'Marked as not a threat')
              )
            }
          >
            {t('lookalikes.falsePositive', 'Not a threat')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() =>
              void act(
                () => resolveExposure(exposure.id, { reason: 'Taken down' }),
                t('lookalikes.resolved', 'Marked as taken down')
              )
            }
          >
            {t('lookalikes.resolve', 'Taken down')}
          </Button>
        </span>
      )}
    </li>
  )
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

function ReviewSection() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canTriage = can(Permission.ExposuresTriage)
  const [state, setState] = useState<ReviewState>('active')
  const {
    exposures,
    total,
    error,
    isLoading,
    mutate,
    allowed,
    hasMore,
    loadingMore,
    loadMore,
    reset,
  } = useLookalikeExposures(state)
  if (!allowed) return null
  const stateLabel = (s: ReviewState) =>
    s === 'active'
      ? t('lookalikes.state.active', 'To review')
      : s === 'accepted'
        ? t('lookalikes.state.accepted', 'Ours or benign')
        : s === 'false_positive'
          ? t('lookalikes.state.falsePositive', 'Not a threat')
          : t('lookalikes.state.resolved', 'Taken down')
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('lookalikes.reviewTitle', 'Registered lookalikes')}
        </CardTitle>
        <CardDescription>
          {t(
            'lookalikes.reviewDescription',
            'Domains registered by someone that imitate yours. Mail servers or a certificate make phishing more likely.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Tabs
          value={state}
          onValueChange={(v) => {
            setState(v as ReviewState)
            reset()
          }}
        >
          <TabsList>
            {REVIEW_STATES.map((s) => (
              <TabsTrigger key={s} value={s}>
                {stateLabel(s)}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        {error ? (
          <ErrorState
            title={t('lookalikes.errorTitle', 'lookalike domains')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <RowsSkeleton />
        ) : exposures.length === 0 ? (
          <EmptyState
            icon={Copy}
            card={false}
            title={t('lookalikes.emptyReviewTitle', 'Nothing here')}
            description={t('lookalikes.emptyReview', 'No registered lookalike in this state.')}
          />
        ) : (
          <>
            <ul className="divide-y">
              {exposures.map((e) => (
                <ReviewRow
                  key={e.id}
                  exposure={e}
                  canTriage={canTriage}
                  onChanged={() => void mutate()}
                />
              ))}
            </ul>
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-xs text-muted-foreground">
                {t('lookalikes.shownOf', '{shown} of {total}', { shown: exposures.length, total })}
              </p>
              {hasMore && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={loadingMore}
                  onClick={() => void loadMore()}
                >
                  {loadingMore && <Loader2 className="me-1 h-4 w-4 animate-spin" aria-hidden />}
                  {t('lookalikes.loadMore', 'Load more')}
                </Button>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export function EASMLookalikes() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWrite = can(Permission.ScopeWrite)
  const canDelete = can(Permission.ScopeDelete)
  const { watches, techniques, max, error, isLoading, mutate } = useLookalikeWatches()
  const [domain, setDomain] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [maxN, setMaxN] = useState(300)
  const [saving, setSaving] = useState(false)
  const [removing, setRemoving] = useState<LookalikeWatch | null>(null)

  const add = async () => {
    if (!domain.trim()) return
    setSaving(true)
    try {
      await createLookalikeWatch({
        domain: domain.trim(),
        techniques: selected,
        max_candidates: maxN,
      })
      toast.success(t('lookalikes.added', 'Watching {domain}', { domain: domain.trim() }))
      setDomain('')
      void mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, t('lookalikes.addFailed', 'Could not watch the domain')))
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!removing?.id) return
    try {
      await deleteLookalikeWatch(removing.id)
      toast.success(t('lookalikes.removed', 'No longer watched'))
      setRemoving(null)
      void mutate()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('lookalikes.removeFailed', 'Could not stop watching the domain'))
      )
    }
  }

  if (error) {
    return (
      <ErrorState
        title={t('lookalikes.errorTitle', 'lookalike domains')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('lookalikes.watchesTitle', 'Watched domains')}
          </CardTitle>
          <CardDescription>
            {t(
              'lookalikes.watchesDescription',
              'Your root domains (a permanent domain scope entry or a verified domain) and their lookalikes. Checks are passive: DNS lookups and Certificate Transparency, daily for registered lookalikes and weekly for the rest. No lookalike host is contacted.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {canWrite && watches.length < max && (
            <div
              className="space-y-3 rounded-md border p-3"
              role="group"
              aria-label={t('lookalikes.addLabel', 'Watch a domain')}
            >
              <div className="flex flex-wrap items-end gap-2">
                <div className="min-w-56 flex-1 space-y-1">
                  <Label htmlFor="lookalike-domain">{t('lookalikes.domain', 'Root domain')}</Label>
                  <Input
                    id="lookalike-domain"
                    value={domain}
                    maxLength={253}
                    placeholder={t('lookalikes.domainPlaceholder', 'example.com')}
                    onChange={(e) => setDomain(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault()
                        void add()
                      }
                    }}
                  />
                </div>
                <Button
                  type="button"
                  disabled={saving || !domain.trim() || !maxValid(maxN)}
                  onClick={() => void add()}
                >
                  <Plus className="me-1 h-4 w-4" aria-hidden />
                  {t('lookalikes.add', 'Watch')}
                </Button>
              </div>
              <WatchSettings
                techniques={techniques}
                selected={selected}
                onChange={setSelected}
                max={maxN}
                onMax={setMaxN}
                idPrefix="new-watch"
              />
            </div>
          )}
          {isLoading ? (
            <RowsSkeleton />
          ) : watches.length === 0 ? (
            <EmptyState
              icon={Copy}
              card={false}
              title={t('lookalikes.emptyTitle', 'No watched domains')}
              description={t(
                'lookalikes.empty',
                'Watch one of your root domains to find lookalikes registered by others.'
              )}
            />
          ) : (
            <ul className="divide-y">
              {watches.map((w) => (
                <WatchRow
                  key={w.id}
                  watch={w}
                  techniques={techniques}
                  canWrite={canWrite}
                  canDelete={canDelete}
                  onChanged={() => void mutate()}
                  onRemove={setRemoving}
                />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
      <ReviewSection />
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={t('lookalikes.removeTitle', 'Stop watching {domain}?', {
          domain: removing?.domain ?? '',
        })}
        desc={t(
          'lookalikes.removeDesc',
          'Its open lookalike exposures are resolved and its candidates are dropped.'
        )}
        confirmText={t('lookalikes.removeButton', 'Stop watching')}
        destructive
        typeToConfirm={removing ? confirmName(removing.domain, removing.id ?? '') : undefined}
        handleConfirm={() => void remove()}
      />
    </div>
  )
}
