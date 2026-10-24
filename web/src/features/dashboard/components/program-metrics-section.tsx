/**
 * CTEM program metrics: the ctem.org program KPIs that can be computed
 * honestly from stored data (GET /api/v1/dashboard/program-metrics).
 *
 * The exact definitions are owned by the API (api/internal/app/module/dashboard.go,
 * api/docs/architecture/program-metrics.md); the
 * tooltips below restate them in plain words. A metric with no qualifying
 * sample comes back null and renders "—" — never 0 or 100%. No value is ever
 * coloured: ctem.org sets no universal target for these, so any red/green
 * would be an invented threshold.
 */

'use client'

import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { StatsCard, ErrorState } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import {
  Radar,
  Wrench,
  UserCheck,
  Route,
  FlaskConical,
  UserPlus,
  RefreshCcw,
  ShieldOff,
} from 'lucide-react'
import { useProgramMetrics } from '../hooks/use-ctem-dashboard'
import { formatDurationHours, formatRatePct } from '../lib/program-health'

const NOT_MEASURED = '—'
const K = 'insights.programMetrics'

type Translate = ReturnType<typeof useTranslation>['t']

type Duration = {
  mean_hours?: number | null
  median_hours?: number | null
  sample_size?: number
  unmeasured?: number
}

type ControlRow = {
  control: string
  total: number
  covered: number
  lacking: number
  unknown: number
  gap_pct?: number | null
}

function valueClass(display: string | null): string | undefined {
  return display === null ? 'text-muted-foreground' : 'tabular-nums'
}

/** "{count} asset" / "{count} assets" through the dictionary. */
function counted(t: Translate, noun: string, n: number | null | undefined): string {
  const count = n ?? 0
  const form = count === 1 ? 'one' : 'other'
  return t(`${K}.noun.${noun}.${form}`, `${count} ${noun}${count === 1 ? '' : 's'}`, {
    count: count.toLocaleString(),
  })
}

/** Caption under a duration tile: median and sample, or why it is empty. */
function durationCaption(
  t: Translate,
  d: Duration | undefined,
  noun: string,
  untimedKey: string,
  untimedFallback: string,
  emptyKey: string,
  emptyFallback: string
): string {
  if (formatDurationHours(d?.mean_hours) !== null) {
    const base = t(`${K}.caption.median`, 'Median {median} · {sample}', {
      median: formatDurationHours(d?.median_hours) ?? NOT_MEASURED,
      sample: counted(t, noun, d?.sample_size),
    })
    return d?.unmeasured
      ? `${base} ${t(`${K}.caption.plusUntimed`, '(+{count} not timed yet)', { count: d.unmeasured })}`
      : base
  }
  if (d?.unmeasured) {
    return t(untimedKey, untimedFallback, { items: counted(t, noun, d.unmeasured) })
  }
  return t(emptyKey, emptyFallback)
}

export function ProgramMetricsSection({
  tenantId,
  days,
}: {
  tenantId: string | null
  days: number
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useProgramMetrics(tenantId, days)

  const mttd = data?.mttd_internet_facing as Duration | undefined
  const mttr = data?.mttr_validated as Duration | undefined
  const mttv = data?.mttv as Duration | undefined
  const tto = data?.time_to_owner_internet_facing as Duration | undefined
  const oa = data?.owner_acceptance
  const cc = data?.cycle_completion
  const controls = (data?.control_coverage ?? []) as ControlRow[]

  const mttdDisplay = formatDurationHours(mttd?.mean_hours)
  const mttrDisplay = formatDurationHours(mttr?.mean_hours)
  const mttvDisplay = formatDurationHours(mttv?.mean_hours)
  const ttoDisplay = formatDurationHours(tto?.mean_hours)
  const oaDisplay = formatRatePct(oa?.rate_pct)
  const ccDisplay = formatRatePct(cc?.rate_pct)

  const mttdCaption = durationCaption(
    t,
    mttd,
    'asset',
    `${K}.mttd.untimed`,
    '{items} with no detection signal yet',
    `${K}.mttd.empty`,
    'No new internet-facing assets in this period'
  )
  const ttoCaption = durationCaption(
    t,
    tto,
    'asset',
    `${K}.timeToOwner.untimed`,
    '{items} still without an owner',
    `${K}.timeToOwner.empty`,
    'No new internet-facing assets in this period'
  )
  const mttvCaption = durationCaption(
    t,
    mttv,
    'finding',
    `${K}.mttv.untimed`,
    '{items} not validated yet',
    `${K}.mttv.empty`,
    'No P0 or P1 findings detected in this period'
  )
  const mttrCaption =
    mttrDisplay !== null
      ? t(`${K}.caption.median`, 'Median {median} · {sample}', {
          median: formatDurationHours(mttr?.median_hours) ?? NOT_MEASURED,
          sample: counted(t, 'finding', mttr?.sample_size),
        })
      : t(`${K}.mttr.empty`, 'No validated exposures resolved in this period')

  const decided = (oa?.accepted ?? 0) + (oa?.missed ?? 0)
  const oaCaption =
    oaDisplay !== null
      ? t(`${K}.acceptance.caption`, '{accepted} of {decided} in SLA', {
          accepted: (oa?.accepted ?? 0).toLocaleString(),
          decided: counted(t, 'assignment', decided),
        }) +
        (oa?.pending
          ? ` · ${t(`${K}.acceptance.pending`, '{count} pending', { count: oa.pending })}`
          : '')
      : oa?.pending
        ? t(`${K}.acceptance.allPending`, '{items} still inside the SLA window', {
            items: counted(t, 'assignment', oa.pending),
          })
        : t(`${K}.acceptance.empty`, 'No assignments with an SLA in this period')

  const ccCaption =
    ccDisplay !== null
      ? t(`${K}.cycles.caption`, '{onTime} of {due} on time · {late} late · {open} open', {
          onTime: (cc?.closed_on_time ?? 0).toLocaleString(),
          due: counted(t, 'cycle', cc?.due),
          late: (cc?.closed_late ?? 0).toLocaleString(),
          open: (cc?.open ?? 0).toLocaleString(),
        }) +
        (formatRatePct(cc?.mean_charter_completion_pct) !== null
          ? ` · ${t(`${K}.cycles.charter`, 'criteria met {pct}', {
              pct: formatRatePct(cc?.mean_charter_completion_pct) ?? NOT_MEASURED,
            })}`
          : '')
      : t(`${K}.cycles.empty`, 'No cycle was due in this period')

  const controlTitle: Record<string, string> = {
    edr: t(`${K}.controls.edr.title`, 'Critical hosts without EDR'),
    mfa: t(`${K}.controls.mfa.title`, 'Critical accounts without MFA'),
    logging: t(`${K}.controls.logging.title`, 'Critical storage without logging'),
  }
  const controlInfo: Record<string, string> = {
    edr: t(
      `${K}.controls.edr.info`,
      'Hosts rated critical or marked as crown jewels whose "EDR installed" attribute is false or not recorded. Not recorded counts as a gap: no source has reported EDR on the host.'
    ),
    mfa: t(
      `${K}.controls.mfa.info`,
      'Cloud accounts and identities rated critical or marked as crown jewels whose "MFA" attribute is false or not recorded. Not recorded counts as a gap.'
    ),
    logging: t(
      `${K}.controls.logging.info`,
      'Storage assets rated critical or marked as crown jewels whose "Logging" attribute is false or not recorded. Not recorded counts as a gap.'
    ),
  }

  const measuredLabel = (title: string) => t(`${K}.infoLabel`, 'How {title} is measured', { title })

  const tiles = [
    {
      title: t(`${K}.mttd.title`, 'Time to detect internet-facing assets'),
      display: mttdDisplay,
      caption: mttdCaption,
      icon: Radar,
      info: t(
        `${K}.mttd.info`,
        'Assets first seen in this period that are internet-facing now. Measured from when the asset was first seen to the earliest sign it was known to be internet-facing: its exposure being set to public, an internet-exposure change in its history, its first exposure event, or its first finding. Known at discovery counts as 0 h. Assets with no such sign are not averaged.'
      ),
    },
    {
      title: t(`${K}.timeToOwner.title`, 'Time to assign an owner'),
      display: ttoDisplay,
      caption: ttoCaption,
      icon: UserPlus,
      info: t(
        `${K}.timeToOwner.info`,
        'The same new internet-facing assets. Measured from when the asset was first seen to when its first owner (a person or a group) was assigned. An owner set before discovery counts as 0 h. Assets still without an owner are not averaged and are listed below the value.'
      ),
    },
    {
      title: t(`${K}.mttv.title`, 'Time to validate priority exposures'),
      display: mttvDisplay,
      caption: mttvCaption,
      icon: FlaskConical,
      info: t(
        `${K}.mttv.info`,
        'P0 and P1 findings first detected in this period. Measured from detection to the first conclusive validation: reproduced or not reproduced. Inconclusive or failed runs do not count. False positives and duplicates are left out.'
      ),
    },
    {
      title: t(`${K}.mttr.title`, 'Time to remediate validated exposures'),
      display: mttrDisplay,
      caption: mttrCaption,
      icon: Wrench,
      info: t(
        `${K}.mttr.info`,
        'Findings a validation run reproduced (outcome "detected", still exploitable) and that were then resolved or verified in this period. Measured from the first reproducing validation to resolution. False positives, accepted risk and fixes made before validation are excluded.'
      ),
    },
    {
      title: t(`${K}.acceptance.title`, 'Owner acceptance rate'),
      display: oaDisplay,
      caption: oaCaption,
      icon: UserCheck,
      info: t(
        `${K}.acceptance.info`,
        'Findings assigned in this period to a named owner. Accepted when that owner changed status, triaged, commented, updated remediation or resolved it before the finding’s SLA deadline. Missed when the deadline passed without that. Assignments still inside their SLA window, without an SLA, or handed to someone else first are left out of the rate.'
      ),
    },
    {
      title: t(`${K}.cycles.title`, 'Cycles completed on time'),
      display: ccDisplay,
      caption: ccCaption,
      icon: RefreshCcw,
      info: t(
        `${K}.cycles.info`,
        'CTEM cycles whose end date fell in this period. On time when the cycle was closed by the end of its end date. "Criteria met" is the average share of measurable charter success criteria met at close.'
      ),
    },
    {
      title: t(`${K}.timeToBreak.title`, 'Time to break attack paths'),
      display: null,
      caption: t(`${K}.timeToBreak.caption`, 'Not measured: attack-path history isn’t stored'),
      icon: Route,
      info: t(
        `${K}.timeToBreak.info`,
        'Not computed. Attack paths are calculated on demand from the current asset graph and never stored, and exposure and relationship changes keep no history — so there is no record of when a path opened or when one of its links was fixed. Any number here would be invented.'
      ),
    },
  ]

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-base font-semibold">{t(`${K}.title`, 'CTEM program metrics')}</h2>
        <p className="text-sm text-muted-foreground">
          {t(
            `${K}.description`,
            'How fast the program detects, validates, fixes and takes ownership. “—” means there is not enough data to measure it yet.'
          )}
        </p>
      </div>

      {error ? (
        <ErrorState
          title={t(`${K}.errorTitle`, 'program metrics')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-32" />
              </CardHeader>
              <CardContent>
                <Skeleton className="mb-2 h-8 w-20" />
                <Skeleton className="h-3 w-36" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {tiles.map((tile) => (
              <StatsCard
                key={tile.title}
                title={tile.title}
                value={tile.display ?? NOT_MEASURED}
                valueClassName={valueClass(tile.display)}
                description={tile.caption}
                icon={tile.icon}
                info={tile.info}
                infoLabel={measuredLabel(tile.title)}
              />
            ))}
          </div>

          {controls.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-medium">
                {t(`${K}.controls.heading`, 'Critical assets lacking a control')}
              </h3>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                {controls.map((row) => {
                  const display = formatRatePct(row.gap_pct)
                  const title = controlTitle[row.control] ?? row.control
                  return (
                    <StatsCard
                      key={row.control}
                      title={title}
                      value={display ?? NOT_MEASURED}
                      valueClassName={valueClass(display)}
                      description={
                        display !== null
                          ? t(
                              `${K}.controls.caption`,
                              '{lacking} lacking · {unknown} not recorded · of {total}',
                              {
                                lacking: row.lacking.toLocaleString(),
                                unknown: row.unknown.toLocaleString(),
                                total: counted(t, 'asset', row.total),
                              }
                            )
                          : t(`${K}.controls.empty`, 'No critical assets of this kind')
                      }
                      icon={ShieldOff}
                      info={controlInfo[row.control]}
                      infoLabel={measuredLabel(title)}
                    />
                  )
                })}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}
