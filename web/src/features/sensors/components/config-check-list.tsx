'use client'

/**
 * Sensor setup report (research/26-sensor-config-doctor.md §4.8): the
 * checks a sensor ran on its own configuration, grouped by area, each with
 * what the platform saw, why it matters and a copyable fix.
 *
 * Threat model (a compromised sensor phishing the admin): everything the
 * sensor wrote (summary, excerpt, observed values, the id of a check the
 * catalog does not know) is data. It is rendered only as React text: in a
 * <pre> for multi-line output, with control and bidi characters made visible,
 * never as HTML or markdown and never auto-linked. Titles, explanations and
 * fix snippets come from the platform catalog through the API; an unknown
 * check gets no fix even if one were sent. Docs links are links only when
 * they point at docs.openctem.io or a same-origin path.
 */

import { useState } from 'react'
import { BookOpen, Check, KeyRound, X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SafeExternalLink } from '@/components/safe-external-link'
import { useTranslation } from '@/context/i18n-provider'
import {
  DETAIL_CHECK_ICON,
  DetailCallout,
  DetailDisclosure,
  DetailSection,
  DetailSections,
  RelativeTime,
  UntrustedTextBlock,
} from '@/features/shared'
import { useSensorConfigReport } from '@/lib/api/sensor-hooks'
import type {
  Sensor,
  SensorConfigCheck,
  SensorConfigCheckStatus,
  SensorConfigReport,
  SensorConfigSetting,
} from '@/lib/api/sensor-types'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

import { ConfigHealthTag, SensorTag } from './sensor-cells'
import {
  CHECK_STATUS_LABEL,
  FIX_FORMATS,
  checkStatusIcon,
  countParts,
  defaultFixFormat,
  fixFormats,
  groupChecks,
  safeDocsHref,
} from '../lib/config-report'

type T = ReturnType<typeof useTranslation>['t']

// ---------------------------------------------------------------------------
// Fix snippets
// ---------------------------------------------------------------------------

/**
 * The fix for one check, one tab per install format the catalog has, each
 * with Copy (the exact snippet). The first tab is the one matching how the
 * sensor runs.
 */
export function FixSnippetTabs({
  fix,
  runtimeKind,
}: {
  fix: SensorConfigCheck['fix']
  runtimeKind?: string
}) {
  const { t } = useTranslation()
  const formats = fixFormats(fix)
  const [picked, setPicked] = useState<string | undefined>(undefined)
  if (formats.length === 0 || !fix) return null
  const active =
    picked && formats.includes(picked) ? picked : defaultFixFormat(formats, runtimeKind)
  const shown = FIX_FORMATS.filter((f) => formats.includes(f.key))
  return (
    <div className="min-w-0 space-y-2" data-slot="config-fix">
      <p className="text-xs font-medium">{t('sensors.setup.fix', 'Fix')}</p>
      <Tabs value={active} onValueChange={setPicked}>
        <TabsList className="no-scrollbar max-w-full overflow-x-auto">
          {shown.map((f) => (
            <TabsTrigger key={f.key} value={f.key}>
              {f.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {shown.map((f) => (
          <TabsContent key={f.key} value={f.key} className="mt-2">
            <UntrustedTextBlock text={fix[f.key] ?? ''} label={`Fix (${f.label})`} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  )
}

// ---------------------------------------------------------------------------
// One check
// ---------------------------------------------------------------------------

function StatusIcon({ status, t }: { status: string; t: T }) {
  const { icon: Icon, className } = DETAIL_CHECK_ICON[checkStatusIcon(status)]
  const label = CHECK_STATUS_LABEL[status as SensorConfigCheckStatus]
  return (
    <Icon
      className={cn('mt-0.5 h-4 w-4 shrink-0', className)}
      aria-label={label ? t(label.key, label.label) : toDisplayText(status, 32)}
      role="img"
    />
  )
}

function CheckBody({
  check: c,
  runtimeKind,
  t,
}: {
  check: SensorConfigCheck
  runtimeKind?: string
  t: T
}) {
  const docs = safeDocsHref(c.docs_url)
  const observed = (c.observed ?? []).filter((o) => o && (o.label || o.value))
  const keys = c.keys ?? []
  return (
    <div className="min-w-0 space-y-2">
      {c.known && c.why && (
        <p className="text-sm break-words text-muted-foreground">{toDisplayText(c.why)}</p>
      )}
      {!c.known && (
        <p className="text-xs text-muted-foreground">
          {t(
            'sensors.setup.unknownCheck',
            'The platform does not know this check yet (a newer sensor). Its data is shown as the sensor sent it.'
          )}
        </p>
      )}
      {observed.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium">{t('sensors.setup.observed', 'What we saw')}</p>
          <dl className="grid grid-cols-[minmax(0,8rem)_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs">
            {observed.map((o, i) => (
              <div key={`${o.label}:${i}`} className="contents">
                <dt className="truncate text-muted-foreground">{toDisplayText(o.label, 64)}</dt>
                <dd className="min-w-0 font-mono break-all" dir="ltr">
                  {toDisplayText(o.value, 512)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
      {c.summary && (
        <UntrustedTextBlock
          text={c.summary}
          label={t('sensors.setup.sensorMessage', 'Sensor message')}
        />
      )}
      {c.excerpt && (
        <UntrustedTextBlock text={c.excerpt} label={t('sensors.setup.toolOutput', 'Tool output')} />
      )}
      {(keys.length > 0 || docs) && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {keys.length > 0 && (
            <span className="inline-flex items-center gap-1 text-muted-foreground">
              <KeyRound className="h-3 w-3" aria-hidden />
              {t('sensors.setup.settings', 'Settings')}
            </span>
          )}
          {keys.map((k) => (
            <SensorTag key={k}>
              <span className="font-mono">{toDisplayText(k, 64)}</span>
            </SensorTag>
          ))}
          {docs && (
            <SafeExternalLink
              href={docs}
              className="ms-auto inline-flex items-center gap-1 text-primary hover:underline"
            >
              <BookOpen className="h-3 w-3" aria-hidden />
              {t('sensors.setup.docs', 'Docs')}
            </SafeExternalLink>
          )}
        </div>
      )}
      {c.known && <FixSnippetTabs fix={c.fix} runtimeKind={runtimeKind} />}
    </div>
  )
}

function CheckRow({ check: c, runtimeKind }: { check: SensorConfigCheck; runtimeKind?: string }) {
  const { t } = useTranslation()
  // Problems open; passed and skipped checks fold their details away.
  const folded = c.status === 'pass' || c.status === 'skip'
  return (
    <li
      className="flex items-start gap-2.5 px-3 py-2.5 text-sm"
      data-check={c.id}
      data-status={c.status}
    >
      <StatusIcon status={c.status} t={t} />
      <div className="min-w-0 flex-1 space-y-1.5">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="font-medium break-words">
            {toDisplayText(c.known ? c.title : c.id, 200)}
          </span>
          {c.known && (
            <span className="font-mono text-[11px] text-muted-foreground" dir="ltr">
              {toDisplayText(c.id, 96)}
            </span>
          )}
        </div>
        {folded ? (
          <DetailDisclosure summary={t('sensors.setup.details', 'Details')}>
            <div className="pt-2">
              <CheckBody check={c} runtimeKind={runtimeKind} t={t} />
            </div>
          </DetailDisclosure>
        ) : (
          <CheckBody check={c} runtimeKind={runtimeKind} t={t} />
        )}
      </div>
    </li>
  )
}

// ---------------------------------------------------------------------------
// Settings presence (never values)
// ---------------------------------------------------------------------------

export function ConfigSettingsTable({ settings }: { settings: SensorConfigSetting[] }) {
  const { t } = useTranslation()
  if (settings.length === 0) return null
  return (
    <DetailDisclosure
      summary={t('sensors.setup.settingsSummary', 'Declared settings ({n})', {
        n: settings.length,
      })}
    >
      <div className="mt-2 overflow-x-auto rounded-lg border">
        <table className="w-full text-xs" aria-label={t('sensors.setup.settingsTable', 'Settings')}>
          <thead className="bg-muted/40 text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-start font-medium">
                {t('sensors.setup.col.name', 'Name')}
              </th>
              <th className="px-3 py-1.5 text-start font-medium">
                {t('sensors.setup.col.set', 'Set')}
              </th>
              <th className="px-3 py-1.5 text-start font-medium">
                {t('sensors.setup.col.source', 'Source')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {settings.map((s) => (
              <tr key={s.name} data-setting={s.name}>
                <td className="px-3 py-1.5">
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="font-mono break-all" dir="ltr">
                      {toDisplayText(s.name, 64)}
                    </span>
                    {s.secret && (
                      <SensorTag tone="info">
                        {t('sensors.setup.secret', 'secret · value never leaves the sensor')}
                      </SensorTag>
                    )}
                    {!s.valid && (
                      <SensorTag tone="warning">{t('sensors.setup.invalid', 'invalid')}</SensorTag>
                    )}
                  </span>
                </td>
                <td className="px-3 py-1.5">
                  {s.set ? (
                    <Check
                      className="h-3.5 w-3.5 text-success"
                      role="img"
                      aria-label={t('sensors.setup.isSet', 'set')}
                    />
                  ) : (
                    <X
                      className="h-3.5 w-3.5 text-muted-foreground"
                      role="img"
                      aria-label={t('sensors.setup.notSet', 'not set')}
                    />
                  )}
                </td>
                <td className="px-3 py-1.5 text-muted-foreground">{toDisplayText(s.source, 16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DetailDisclosure>
  )
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/**
 * The setup report as a checklist: a header (health, last checked, counts),
 * notices (derived, stale, truncated), then the checks grouped by area and
 * the declared settings. Shared by the sensor drawer and, later, the install
 * dialog.
 */
export function ConfigCheckList({ report }: { report: SensorConfigReport }) {
  const { t } = useTranslation()
  const checks = report.checks ?? []
  const groups = groupChecks(checks)
  const parts = countParts(report.counts)
  return (
    <div className="space-y-4" data-slot="config-check-list">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <ConfigHealthTag health={report.health} always />
        {report.observed_at && (
          <span className="text-xs text-muted-foreground">
            {t('sensors.setup.lastChecked', 'Last checked')}{' '}
            <RelativeTime date={report.observed_at} />
          </span>
        )}
        <span className="text-xs text-muted-foreground tabular-nums" data-slot="config-counts">
          {parts
            .map((p) => t(`sensors.setup.count.${p.status}`, COUNT_FALLBACK[p.status], { n: p.n }))
            .join(' · ')}
        </span>
      </div>

      {report.state === 'derived' && (
        <DetailCallout
          tone="info"
          title={t('sensors.setup.derivedTitle', 'Derived from the heartbeat')}
        >
          {report.derived_note
            ? toDisplayText(report.derived_note, 300)
            : t(
                'sensors.setup.derivedFallback',
                'This sensor does not send a setup report; these checks are what the platform can tell from its heartbeat.'
              )}
        </DetailCallout>
      )}
      {report.stale && (
        <DetailCallout tone="warning" title={t('sensors.setup.staleTitle', 'Report out of date')}>
          {t(
            'sensors.setup.staleBody',
            'The sensor has not sent its current setup report, so these results may no longer be true.'
          )}
        </DetailCallout>
      )}
      {report.truncated && (
        <DetailCallout tone="warning" title={t('sensors.setup.truncatedTitle', 'Report truncated')}>
          {t(
            'sensors.setup.truncatedBody',
            'The report was too large and the sensor cut it to fit, so some checks are missing.'
          )}
        </DetailCallout>
      )}

      {checks.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('sensors.setup.noChecks', 'The report has no checks.')}
        </p>
      ) : (
        <DetailSections>
          {groups.map((g) => (
            <DetailSection
              key={g.group}
              title={t(`sensors.setup.group.${g.group}`, g.label)}
              count={g.checks.length}
            >
              <ul className="divide-y rounded-lg border" aria-label={g.label}>
                {g.checks.map((c, i) => (
                  <CheckRow key={`${c.id}:${i}`} check={c} runtimeKind={report.runtime_kind} />
                ))}
              </ul>
            </DetailSection>
          ))}
        </DetailSections>
      )}

      <ConfigSettingsTable settings={report.settings ?? []} />
    </div>
  )
}

const COUNT_FALLBACK: Record<SensorConfigCheckStatus, string> = {
  pass: '{n} passed',
  warn: '{n} warnings',
  fail: '{n} failed',
  error: '{n} errors',
  skip: '{n} skipped',
}

// ---------------------------------------------------------------------------
// The drawer tab
// ---------------------------------------------------------------------------

/** The drawer's Setup & health tab: loads the report, then the list. */
export function SensorSetupTab({ sensor }: { sensor: Pick<Sensor, 'id'> }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSensorConfigReport(sensor.id)

  if (isLoading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }
  if (error) {
    return (
      <div className="space-y-2 text-sm" role="alert">
        <p>{t('sensors.setup.loadError', 'The setup report could not be loaded.')}</p>
        <Button variant="outline" size="sm" onClick={() => mutate()}>
          {t('sensors.setup.retry', 'Retry')}
        </Button>
      </div>
    )
  }
  if (!data || data.state === 'none') {
    return (
      <p className="text-sm text-muted-foreground">
        {t(
          'sensors.setup.empty',
          'This sensor has not sent a setup report yet. Sensors send one when they start and after a configuration change.'
        )}
      </p>
    )
  }
  return <ConfigCheckList report={data} />
}
