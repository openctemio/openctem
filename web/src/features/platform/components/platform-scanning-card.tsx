'use client'

/**
 * Platform scanning on the Sensors page: the platform operator's shared
 * scanning as a service the organization can send scans to. It names regions,
 * their state, the tools it runs and the organization's own jobs, and says
 * which scans can run there. Never a sensor (the API returns none) and no
 * other organization's load. Renders nothing when the organization may not
 * use platform scanning: no upsell.
 */

import Link from '@/components/link'
import { Cloud } from 'lucide-react'

import { useScopeSettingsApi } from '@/features/scope'
import { usePlatformScanning } from '@/lib/api/platform-hooks'
import type { PlatformScanningStatus } from '@/lib/api/platform-types'
import { cn } from '@/lib/utils'

/** Theme tokens only: a tint and a dot per state; the word carries the meaning. */
const STATUS: Record<PlatformScanningStatus, { label: string; pill: string; dot: string }> = {
  available: { label: 'Available', pill: 'bg-success/15 text-success', dot: 'bg-success' },
  busy: { label: 'Busy, jobs wait', pill: 'bg-warning/15 text-warning', dot: 'bg-warning' },
  unavailable: {
    label: 'Unavailable, jobs wait',
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
      {m.label}
    </span>
  )
}

/** How many tools are listed before "+N more". */
const TOOLS_SHOWN = 8

export function PlatformScanningCard({ className }: { className?: string }) {
  const { data, offered } = usePlatformScanning()
  const { data: scope } = useScopeSettingsApi(offered)
  if (!offered || !data) return null

  const status = data.status ?? 'unavailable'
  const proof = scope?.active_proof && scope.active_proof !== 'off'
  const tools = data.tools.slice(0, TOOLS_SHOWN)
  const moreTools = data.tools.length - tools.length
  const { queued, running } = data.your_jobs

  return (
    <section
      aria-labelledby="platform-scanning-title"
      className={cn('rounded-lg border bg-card px-4 py-3 text-sm', className)}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Cloud className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        <h2 id="platform-scanning-title" className="font-medium">
          Platform scanning
        </h2>
        <PlatformStatusPill status={status} />
        <span className="text-muted-foreground">
          Shared scanning run by the platform operator, for public targets.
        </span>
      </div>

      <dl className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">Regions</dt>
          <dd className="mt-1">
            <ul className="space-y-1">
              {data.regions.map((r) => (
                <li key={r.name || 'default'} className="flex items-center justify-between gap-2">
                  <span className="truncate">{r.name || 'Default region'}</span>
                  <PlatformStatusPill status={r.status} />
                </li>
              ))}
            </ul>
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">Tools</dt>
          <dd className="mt-1 flex flex-wrap gap-1">
            {tools.length === 0 ? (
              <span className="text-muted-foreground">None online now</span>
            ) : (
              tools.map((t) => (
                <span key={t} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {t}
                </span>
              ))
            )}
            {moreTools > 0 && (
              <span className="text-xs text-muted-foreground">+{moreTools} more</span>
            )}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">Your platform jobs</dt>
          <dd className="mt-1 tabular-nums">
            {queued} queued, {running} running
          </dd>
        </div>
      </dl>

      <ul className="mt-3 list-disc space-y-1 border-t ps-5 pt-3 text-muted-foreground">
        <li>
          Public targets only. Internal addresses, asset groups and targets in a scan zone run on
          your own sensors.
        </li>
        {proof && (
          <li>
            Every target needs a verified domain of your organization.{' '}
            <Link href="/scope?tab=proof" className="font-medium text-foreground underline">
              Verify a domain
            </Link>
          </li>
        )}
        {data.queue_limit_minutes ? (
          <li>A job that waits {data.queue_limit_minutes} minutes for a free slot fails.</li>
        ) : null}
        <li>Choose where a scan runs in its Sensor setting (Auto, Your sensors or Platform).</li>
      </ul>
    </section>
  )
}
