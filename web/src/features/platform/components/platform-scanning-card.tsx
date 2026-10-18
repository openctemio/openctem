'use client'

/**
 * Shared sensors on the Sensors page (api docs/rfcs/RFC-100-shared-sensors.md):
 * the instance's shared sensors as a service the organization can send scans
 * to. It names regions, their state, the tools they run, the organization's
 * own jobs and the egress addresses to allowlist, and says which scans can
 * run there. Never a sensor (the API returns none) and no other
 * organization's load. Renders nothing when the organization may not use
 * shared sensors: no upsell.
 */

import { Cloud, Copy } from 'lucide-react'
import { toast } from 'sonner'

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useScopeSettingsApi } from '@/features/scope'
import { usePlatformScanning } from '@/lib/api/platform-hooks'
import type { PlatformEgress, PlatformScanningStatus } from '@/lib/api/platform-types'
import { usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'

/** Where the owner's opt-out switch lives (organization settings). */
export const SHARED_SENSORS_OPT_OUT_HREF = '/settings/scanning/sensor-safety#shared-sensors'

/** Theme tokens only: a tint and a dot per state; the word carries the meaning. */
const STATUS: Record<PlatformScanningStatus, { key: string; pill: string; dot: string }> = {
  available: {
    key: 'sensors.shared.status.available',
    pill: 'bg-success/15 text-success',
    dot: 'bg-success',
  },
  busy: {
    key: 'sensors.shared.status.busy',
    pill: 'bg-warning/15 text-warning',
    dot: 'bg-warning',
  },
  unavailable: {
    key: 'sensors.shared.status.unavailable',
    pill: 'bg-destructive/15 text-destructive',
    dot: 'bg-destructive',
  },
}

export function PlatformStatusPill({
  status,
  className,
}: {
  status: PlatformScanningStatus
  className?: string
}) {
  const { t } = useTranslation()
  const m = STATUS[status] ?? STATUS.unavailable
  return (
    <span
      data-status={status}
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap',
        m.pill,
        className
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', m.dot)} aria-hidden />
      {t(m.key)}
    </span>
  )
}

/** How many tools are listed before "+N more". */
const TOOLS_SHOWN = 8

function EgressList({ egress }: { egress: PlatformEgress[] }) {
  const { t } = useTranslation()
  const copy = async (addresses: string[]) => {
    try {
      await navigator.clipboard.writeText(addresses.join('\n'))
      toast.success(t('sensors.shared.egress.copied'))
    } catch {
      toast.error(t('sensors.shared.egress.copyFailed'))
    }
  }
  return (
    <div className="mt-3 border-t pt-3">
      <h3 className="text-xs font-medium">{t('sensors.shared.egress.title')}</h3>
      <p className="mt-0.5 text-xs text-muted-foreground">{t('sensors.shared.egress.hint')}</p>
      <ul className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
        {egress.map((e) => {
          const region = e.region || t('sensors.shared.egress.allRegions')
          return (
            <li key={e.region || '*'} className="min-w-0 rounded-md border px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-xs text-muted-foreground">{region}</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2"
                  onClick={() => copy(e.addresses)}
                  aria-label={t('sensors.shared.egress.copyAria', undefined, { region })}
                >
                  <Copy className="h-3.5 w-3.5" aria-hidden />
                </Button>
              </div>
              <ul className="mt-1 space-y-0.5">
                {e.addresses.map((a) => (
                  <li key={a} className="font-mono text-xs break-all">
                    {a}
                  </li>
                ))}
              </ul>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export function PlatformScanningCard({ className }: { className?: string }) {
  const { t } = useTranslation()
  const { isAdmin } = usePermissions()
  const { data, offered } = usePlatformScanning()
  const { data: scope } = useScopeSettingsApi(offered)
  if (!offered || !data) return null

  const status = data.status ?? 'unavailable'
  const proof = scope?.active_proof && scope.active_proof !== 'off'
  const tools = data.tools.slice(0, TOOLS_SHOWN)
  const moreTools = data.tools.length - tools.length
  const { queued, running } = data.your_jobs
  const egress = (data.egress ?? []).filter((e) => e.addresses.length > 0)

  return (
    <section
      aria-labelledby="shared-sensors-title"
      className={cn('rounded-lg border bg-card px-4 py-3 text-sm', className)}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Cloud className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        <h2 id="shared-sensors-title" className="font-medium">
          {t('sensors.shared.title')}
        </h2>
        <PlatformStatusPill status={status} />
        <span className="text-muted-foreground">{t('sensors.shared.subtitle')}</span>
      </div>

      <dl className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t('sensors.shared.regions')}</dt>
          <dd className="mt-1">
            <ul className="space-y-1">
              {data.regions.map((r) => (
                <li key={r.name || 'default'} className="flex items-center justify-between gap-2">
                  <span className="truncate">{r.name || t('sensors.shared.defaultRegion')}</span>
                  <PlatformStatusPill status={r.status} />
                </li>
              ))}
            </ul>
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t('sensors.shared.tools')}</dt>
          <dd className="mt-1 flex flex-wrap gap-1">
            {tools.length === 0 ? (
              <span className="text-muted-foreground">{t('sensors.shared.noTools')}</span>
            ) : (
              tools.map((tool) => (
                <span key={tool} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {tool}
                </span>
              ))
            )}
            {moreTools > 0 && (
              <span className="text-xs text-muted-foreground">
                {t('sensors.shared.moreTools', undefined, { count: moreTools })}
              </span>
            )}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t('sensors.shared.yourJobs')}</dt>
          <dd className="mt-1 tabular-nums">
            {t('sensors.shared.jobCounts', undefined, { queued, running })}
          </dd>
        </div>
      </dl>

      {egress.length > 0 && <EgressList egress={egress} />}

      <ul className="mt-3 list-disc space-y-1 border-t ps-5 pt-3 text-muted-foreground">
        <li>{t('sensors.shared.publicOnly')}</li>
        {proof && (
          <li>
            {t('sensors.shared.proofNeeded')}{' '}
            <Link href="/scope?tab=proof" className="font-medium text-foreground underline">
              {t('sensors.shared.verifyDomain')}
            </Link>
          </li>
        )}
        {data.queue_limit_minutes ? (
          <li>
            {t('sensors.shared.queueLimit', undefined, { minutes: data.queue_limit_minutes })}
          </li>
        ) : null}
        <li>{t('sensors.shared.chooseWhere')}</li>
        {isAdmin() && (
          <li>
            {t('sensors.shared.optOutHint')}{' '}
            <Link
              href={SHARED_SENSORS_OPT_OUT_HREF}
              className="font-medium text-foreground underline"
            >
              {t('sensors.shared.optOutLink')}
            </Link>
          </li>
        )}
      </ul>
    </section>
  )
}
