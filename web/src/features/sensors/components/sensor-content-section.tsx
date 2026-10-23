'use client'

import { useState } from 'react'
import { ChevronRight, Copy, Loader2, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { refreshSensorContent } from '@/lib/api/sensor-content-hooks'
import type { Sensor, SensorContent } from '@/lib/api/sensor-types'
import { copyToClipboard } from '@/lib/clipboard'
import { redactUrlQueries } from '@/lib/redact-url'
import { cn } from '@/lib/utils'

import { SensorTag } from './sensor-cells'
import {
  CONTENT_STATE_META,
  contentAgeSeconds,
  contentAgeText,
  contentCheckedText,
  contentLabel,
  contentState,
  contentStateLabel,
  contentVersionDate,
  formatHours,
  shortDigest,
} from '../lib/content'
import { formatDurationShort, type Tr } from '../lib/format'

function statusCodeOf(err: unknown): number | undefined {
  const code = (err as { statusCode?: unknown } | null)?.statusCode
  return typeof code === 'number' ? code : undefined
}

/**
 * Ask one sensor to refresh its scanner content (POST
 * /sensors/{id}/content/refresh) and say what happened.
 */
export async function requestSensorContentRefresh(sensor: Pick<Sensor, 'id' | 'name'>, t: Tr) {
  try {
    const res = await refreshSensorContent(sensor.id)
    if (res.already_pending) {
      toast.info(t('sensors.contentSection.alreadyQueued', undefined, { name: sensor.name }))
    } else {
      toast.success(t('sensors.contentSection.requested', undefined, { name: sensor.name }))
    }
    return true
  } catch (err) {
    if (statusCodeOf(err) === 409) {
      toast.error(t('sensors.contentSection.unmanaged', undefined, { name: sensor.name }))
    } else {
      toast.error(getErrorMessage(err, t('sensors.contentCells.error')))
    }
    return false
  }
}

function DigestButton({ digest }: { digest: string }) {
  const { t } = useTranslation()
  return (
    <button
      type="button"
      className="inline-flex max-w-full items-center gap-1 rounded-sm font-mono hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      aria-label={t('sensors.contentSection.copyDigest', undefined, { digest })}
      onClick={() => {
        copyToClipboard(digest)
        toast.success(t('sensors.contentSection.digestCopied'))
      }}
    >
      <span className="truncate">{shortDigest(digest)}</span>
      <Copy className="h-3 w-3 shrink-0" aria-hidden />
    </button>
  )
}

/**
 * Age against the policy's limit as a thin bar. Amber only when the API
 * calls the item stale (it may measure from another time than the age).
 */
function AgeMeter({ c, now }: { c: SensorContent; now: number }) {
  const { t } = useTranslation()
  const age = contentAgeSeconds(c, now)
  const limitH = c.max_age_hours ?? 0
  if (age == null || limitH <= 0) return null
  const ratio = age / (limitH * 3600)
  const stale = contentState(c) === 'stale'
  return (
    <span
      role="meter"
      aria-label={t('sensors.contentSection.ageMeter', undefined, {
        percent: Math.round(ratio * 100),
      })}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.min(100, Math.round(ratio * 100))}
      className="inline-block h-1 w-12 shrink-0 overflow-hidden rounded-full bg-muted align-middle"
    >
      <span
        className={cn('block h-full rounded-full', stale ? 'bg-warning' : 'bg-success')}
        style={{ width: `${Math.min(100, Math.max(4, ratio * 100))}%` }}
      />
    </span>
  )
}

function ContentVersion({ c, now }: { c: SensorContent; now: number }) {
  const { t } = useTranslation()
  if (!c.version) return <span>{t('sensors.contentSection.noneInstalled')}</span>
  const built = contentVersionDate(c.version)
  if (built) {
    return (
      <span className="text-foreground" title={c.version}>
        {t('sensors.contentSection.built', undefined, {
          age: formatDurationShort(Math.max(0, (now - built.getTime()) / 1000)),
        })}
      </span>
    )
  }
  return <span className="text-foreground tabular-nums">{c.version}</span>
}

function ContentRow({ c, now }: { c: SensorContent; now: number }) {
  const { t } = useTranslation()
  const state = contentState(c)
  const meta = CONTENT_STATE_META[state]
  const age = contentAgeText(c, now, t)
  const limit = formatHours(c.max_age_hours)
  const checked = contentCheckedText(c, now, t)
  const hasDetails = !!(c.digest || c.source || c.error || c.version)
  return (
    <li className="px-3 py-2.5 text-sm" data-content={c.name} data-state={state}>
      <div className="flex items-center justify-between gap-2">
        <span className="min-w-0 truncate font-medium">{contentLabel(c.name)}</span>
        <SensorTag tone={meta.tone}>{contentStateLabel(state, t)}</SensorTag>
      </div>
      {c.managed ? (
        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-muted-foreground tabular-nums">
          <ContentVersion c={c} now={now} />
          {age && (
            <>
              <span aria-hidden>·</span>
              <span
                className={cn(
                  'inline-flex items-center gap-1.5',
                  state === 'stale' && 'text-warning'
                )}
              >
                {age}
                {limit ? ` · ${t('sensors.contentSection.limit', undefined, { limit })}` : ''}
                <AgeMeter c={c} now={now} />
              </span>
            </>
          )}
          {checked && (
            <>
              <span aria-hidden>·</span>
              <span>{checked}</span>
            </>
          )}
          {c.pinned_version && (
            <>
              <span aria-hidden>·</span>
              <span className={cn(c.pin_mismatch && 'text-warning')}>
                {t('sensors.contentSection.pinned')}{' '}
                <span className="text-foreground">{c.pinned_version}</span>
              </span>
            </>
          )}
        </div>
      ) : (
        <p className="mt-1 text-xs text-muted-foreground">
          {t('sensors.contentSection.unmanagedLine')}
        </p>
      )}
      {/* A plain line on the row; the error itself is under Details. The
          API reports no time for the failure, so none is shown. */}
      {c.error && (
        <p className="mt-1 text-xs text-destructive">{t('sensors.contentSection.lastFailed')}</p>
      )}
      {hasDetails && (
        <details className="group mt-1 text-xs text-muted-foreground">
          <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm select-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [&::-webkit-details-marker]:hidden">
            <ChevronRight
              className="h-3 w-3 transition-transform group-open:rotate-90"
              aria-hidden
            />
            {t('sensors.contentSection.details')}
          </summary>
          <dl className="mt-1.5 grid grid-cols-[4.5rem_minmax(0,1fr)] gap-x-2 gap-y-1 ps-4">
            {c.version && (
              <>
                <dt>{t('sensors.contentSection.version')}</dt>
                <dd className="font-mono break-all text-foreground">{c.version}</dd>
              </>
            )}
            {c.digest && (
              <>
                <dt>{t('sensors.contentSection.digest')}</dt>
                <dd className="min-w-0">
                  <DigestButton digest={c.digest} />
                </dd>
              </>
            )}
            {c.source && (
              <>
                <dt>{t('sensors.contentSection.source')}</dt>
                <dd className="font-mono break-all">{redactUrlQueries(c.source)}</dd>
              </>
            )}
            {c.error && (
              <>
                <dt>{t('sensors.contentSection.error')}</dt>
                <dd className="font-mono break-all text-destructive">
                  {redactUrlQueries(c.error)}
                </dd>
              </>
            )}
          </dl>
        </details>
      )}
    </li>
  )
}

/**
 * The drawer's "Scanner content" section: one compact row per item the
 * sensor scans with (state, version, age against the policy's limit, when it
 * last checked), the digest, source and full error behind "Details", and an
 * admin-only "Refresh content". Renders nothing for a sensor that reports no
 * content.
 */
export function SensorContentSection({
  sensor,
  now,
  canManage,
}: {
  sensor: Pick<Sensor, 'id' | 'name' | 'content' | 'content_refresh_supported'>
  now: number
  canManage: boolean
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const items = sensor.content ?? []
  if (items.length === 0) return null
  const supported = !!sensor.content_refresh_supported

  const refresh = async () => {
    setBusy(true)
    try {
      await requestSensorContentRefresh(sensor, t)
    } finally {
      setBusy(false)
    }
  }

  const button = (
    <Button
      type="button"
      size="sm"
      variant="outline"
      className="h-7 px-2 text-xs"
      disabled={!supported || busy}
      onClick={refresh}
    >
      {busy ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <RefreshCw className="h-3.5 w-3.5" />
      )}
      {t('sensors.contentCells.refresh')}
    </Button>
  )

  return (
    <DetailSection
      title={t('sensors.contentCells.sectionTitle')}
      actions={
        canManage &&
        (supported ? (
          button
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>
              {/* A disabled button gets no pointer events: the span carries the tooltip. */}
              <span tabIndex={0}>{button}</span>
            </TooltipTrigger>
            <TooltipContent>{t('sensors.contentSection.cannotRefresh')}</TooltipContent>
          </Tooltip>
        ))
      }
    >
      <ul className="divide-y rounded-lg border">
        {items.map((c) => (
          <ContentRow key={`${c.tool}:${c.name}`} c={c} now={now} />
        ))}
      </ul>
    </DetailSection>
  )
}
