'use client'

import useSWR from 'swr'
import { ChevronDown, Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
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
