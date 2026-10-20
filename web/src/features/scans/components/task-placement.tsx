'use client'

import useSWR from 'swr'
import { ChevronDown, Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import Link from '@/components/link'

import { useTranslation } from '@/context/i18n-provider'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunTaskPlacement } from '@/lib/api/generated'
import { toDisplayText } from '@/lib/untrusted-text'

import { placementHelp } from '../lib/placement-help'
import type { Translate } from '../lib/translate'
import { CodeHelpLine } from './code-help'

/**
 * The one-line answer to "why is this task still waiting": the reasons that
 * hold it whatever the sensor, else how many sensors can take it (and how
 * many of those are busy), else that none can.
 */
export function placementSummary(p: RunTaskPlacement, t: Translate): string {
  if (!p.queued) return t('scans.placement.notQueued')
  if (p.platform) return t('scans.placement.platform')
  const hostWait = hostWaitSummary(p, t)
  if (hostWait) return hostWait
  if ((p.job_reasons ?? []).length > 0) return t('scans.placement.heldForAll')
  const eligible = p.eligible ?? 0
  const busy = p.busy ?? 0
  if (eligible > 0 && busy === eligible) {
    return t('scans.placement.allBusy', undefined, { count: eligible })
  }
  if (eligible > 0) return t('scans.placement.someCan', undefined, { count: eligible, busy })
  if ((p.evaluated ?? 0) === 0) return t('scans.placement.noSensors')
  return t('scans.placement.noneCan', undefined, { count: p.evaluated ?? 0 })
}

/**
 * Whether the shared fleet was an option for a task none of the
 * organization's sensors may take (research/191 W-1): the run would
 * otherwise wait in silence until its timeout. Null when one of them may.
 */
export function sharedFleetNote(p: RunTaskPlacement, t: Translate): string | null {
  if (!p.queued || p.platform || (p.eligible ?? 0) > 0) return null
  if (p.shared_fleet === 'not_used') return t('scans.placement.sharedNotUsed')
  if (p.shared_fleet === 'not_allowed') return t('scans.placement.sharedNotAllowed')
  return null
}

/**
 * Why a task waits for its hosts, when it does: how many of its hosts other
 * tasks of the organization are scanning, and with which tool and step (the
 * task holding the most). Counts only, never host names. Null when the task
 * does not wait for its hosts.
 */
export function hostWaitSummary(p: RunTaskPlacement, t: Translate): string | null {
  const hw = p.host_wait
  if (!hw || !(p.job_reasons ?? []).includes('host_busy')) return null
  const vars = { held: hw.hosts_held ?? 0, total: hw.hosts_total ?? 0 }
  const top = (hw.holders ?? [])[0]
  let base: string
  if (top?.tool && top.step_key) {
    base = t('scans.placement.hostWaitBy', undefined, {
      ...vars,
      tool: toDisplayText(top.tool),
      step: toDisplayText(top.step_key),
    })
  } else if (top?.tool) {
    base = t('scans.placement.hostWaitTool', undefined, { ...vars, tool: toDisplayText(top.tool) })
  } else {
    base = t('scans.placement.hostWait', undefined, vars)
  }
  return withCanStart(base, hw, t, 'scans.placement.hostWaitFree')
}

type HostWait = NonNullable<RunTaskPlacement['host_wait']>

/**
 * Adds how many of the task's targets are on free hosts, when known, with
 * the dictionary entry key (base, canStart, targets).
 */
function withCanStart(base: string, hw: HostWait, t: Translate, key: string): string {
  const canStart = hw.can_start ?? -1
  const targets = hw.targets ?? 0
  if (canStart < 0 || targets <= 0) return base
  return t(key, undefined, { base, canStart, targets })
}

/**
 * The task list's line for a task waiting for its hosts: how many of its
 * hosts are held, by which tool, step and run (this run, or another run's
 * short id, only when the caller can read that run), and how many of its
 * targets are on free hosts. Counts only, never host names.
 */
export function hostWaitLine(hw: HostWait, runId: string, t: Translate): string {
  const held = hw.hosts_held ?? 0
  const top = (hw.holders ?? [])[0]
  let base: string
  if (top?.tool && top.step_key && top.run_id) {
    const where =
      top.run_id === runId
        ? t('scans.tasks.hostWaitThisRun')
        : t('scans.tasks.hostWaitRun', undefined, { run: top.run_id.slice(0, 8) })
    base = t('scans.tasks.hostWaitBy', undefined, {
      held,
      tool: toDisplayText(top.tool),
      step: toDisplayText(top.step_key),
      where,
    })
  } else if (top?.tool) {
    base = t('scans.tasks.hostWaitTool', undefined, { held, tool: toDisplayText(top.tool) })
  } else {
    base = t('scans.tasks.hostWaitAny', undefined, { held })
  }
  return withCanStart(base, hw, t, 'scans.tasks.hostWaitWithFree')
}

/** The "Why waiting?" toggle of a queued task. */
export function WhyWaitingButton({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  const { t } = useTranslation()
  return (
    <Button
      variant="link"
      size="sm"
      className="mt-1 h-auto gap-1 p-0 text-xs"
      aria-expanded={open}
      onClick={onToggle}
    >
      {t('scans.placement.why')}
      <ChevronDown
        className={
          open ? 'h-3 w-3 rotate-180 transition-transform' : 'h-3 w-3 transition-transform'
        }
        aria-hidden="true"
      />
    </Button>
  )
}

/**
 * Why a queued task waits: asks the API when shown (one request per task
 * the user opens), then shows the summary, each reason with its fix, and,
 * for a caller who may read sensors, each sensor's verdict. Sensor names are
 * the organization's own; platform scanning is never broken down.
 */
export function TaskPlacementPanel({ runId, taskId }: { runId: string; taskId: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useSWR<RunTaskPlacement>(
    scanRunEndpoints.taskPlacement(runId, taskId),
    (url: string) => get<RunTaskPlacement>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  const reasons = [
    ...(data?.job_reasons ?? []).map((code) => ({ code, count: undefined })),
    ...(data?.blocking ?? []).map((b) => ({ code: b.code ?? '', count: b.count })),
  ].filter((r) => r.code)

  return (
    <div className="space-y-2 rounded-md border bg-muted/30 p-3 text-xs" aria-live="polite">
      {isLoading && (
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          <Loader2 className="h-3 w-3 animate-spin motion-reduce:animate-none" aria-hidden />
          {t('scans.placement.loading')}
        </span>
      )}
      {error && <p className="text-destructive">{t('scans.placement.loadFailed')}</p>}
      {data && (
        <>
          <p className="font-medium">{placementSummary(data, t)}</p>
          {sharedFleetNote(data, t) && (
            <p className="text-muted-foreground">{sharedFleetNote(data, t)}</p>
          )}
          {(data.host_wait?.holders ?? [])
            .filter((h) => h.run_id && h.run_id !== runId)
            .slice(0, 1)
            .map((h) => (
              <Link
                key={h.task_id ?? h.run_id}
                href={`/scans/runs?run=${encodeURIComponent(h.run_id ?? '')}`}
                className="text-primary underline-offset-2 hover:underline"
              >
                {t('scans.placement.holderRun')}
              </Link>
            ))}
          {reasons.length > 0 && (
            <div className="grid gap-3 sm:grid-cols-2">
              {reasons.map((r) => (
                <CodeHelpLine key={r.code} help={placementHelp(r.code, t)} count={r.count} />
              ))}
            </div>
          )}
          {data.truncated && (
            <p className="text-muted-foreground">{t('scans.placement.truncated')}</p>
          )}
          {(data.sensors ?? []).length > 0 && (
            <details>
              <summary className="cursor-pointer text-muted-foreground">
                {t('scans.placement.perSensor', undefined, { count: data.sensors?.length ?? 0 })}
              </summary>
              <ul className="mt-1 space-y-0.5">
                {data.sensors?.map((s) => (
                  <li key={s.id} className="flex flex-wrap gap-x-2">
                    <span className="font-medium">{toDisplayText(s.name)}</span>
                    <span className="text-muted-foreground">
                      {s.eligible
                        ? s.busy
                          ? t('scans.placement.sensorBusy')
                          : t('scans.placement.sensorEligible')
                        : (s.reasons ?? []).join(', ')}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  )
}
