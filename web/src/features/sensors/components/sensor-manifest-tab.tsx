'use client'

import { useState } from 'react'
import { AlertTriangle, Copy } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailField, DetailFieldGrid, DetailSection, DetailSections } from '@/features/shared'
import { useSensorManifests } from '@/lib/api/sensor-hooks'
import type { Sensor, SensorManifestVersion, SensorToolContract } from '@/lib/api/sensor-types'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'

import { SensorTag } from './sensor-cells'
import { SensorToolOptions } from './sensor-tool-options'
import { shortDigest } from '../lib/content'
import { agoShort, exactTime } from '../lib/format'
import {
  concurrencyText,
  contractSummary,
  ignoredLooksNewer,
  ignoredReasonLabel,
  isEmptyDiff,
  manifestDiffLines,
  manifestHistory,
  manifestSourceLabel,
  resourcesText,
} from '../lib/manifest'

/** Versions shown before "Show all". */
const HISTORY_PREVIEW = 5

function Digest({ digest, kind = 'manifest' }: { digest: string; kind?: 'manifest' | 'contract' }) {
  const { t } = useTranslation()
  const what =
    kind === 'contract'
      ? t('sensors.manifest.digestWhat.contract', 'Tool contract')
      : t('sensors.manifest.digestWhat.manifest', 'Manifest')
  return (
    <button
      type="button"
      className="inline-flex max-w-full items-center gap-1 rounded-sm font-mono text-xs hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      aria-label={t('sensors.manifest.copyDigestAria', 'Copy {what} digest {digest}', {
        what: what.toLowerCase(),
        digest,
      })}
      title={digest}
      onClick={() => {
        copyToClipboard(digest)
        toast.success(t('sensors.manifest.digestCopied', '{what} digest copied', { what }))
      }}
    >
      <span className="truncate">{shortDigest(digest)}</span>
      <Copy className="h-3 w-3 shrink-0" aria-hidden />
    </button>
  )
}

/** A ported tool's contract: what it is and the output types it may produce. */
function ToolContract({ tool, c }: { tool: string; c: SensorToolContract }) {
  const { t } = useTranslation()
  return (
    <div
      className="space-y-1 rounded-md bg-muted/40 px-2 py-1.5 text-xs"
      aria-label={t('sensors.manifest.toolContractAria', '{tool} tool contract', { tool })}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium">
          {t('sensors.manifest.toolContractTitle', 'Tool contract')}
        </span>
        <span className="text-muted-foreground">{contractSummary(c, t)}</span>
        <span className="text-muted-foreground tabular-nums">v{c.version}</span>
        <Digest digest={c.digest} kind="contract" />
      </div>
      {(c.consumes?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-muted-foreground">
            {t('sensors.manifest.consumes', 'Consumes')}
          </span>
          {c.consumes!.map((v) => (
            <SensorTag key={v}>{v}</SensorTag>
          ))}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-1">
        <span className="text-muted-foreground">{t('sensors.manifest.produces', 'Produces')}</span>
        {c.produces.length === 0 ? (
          <span className="text-muted-foreground">
            {t('sensors.manifest.producesNothing', 'nothing')}
          </span>
        ) : (
          c.produces.map((v) => (
            <SensorTag key={v} tone="info">
              {v}
            </SensorTag>
          ))
        )}
      </div>
    </div>
  )
}

function CurrentManifest({ v, now }: { v: SensorManifestVersion; now: number }) {
  const { t } = useTranslation()
  const m = v.manifest
  const resources = resourcesText(m, t)
  const build = [m.sensor?.name, m.sensor?.version].filter(Boolean).join(' ')
  const sdk = [m.sdk?.name, m.sdk?.version].filter(Boolean).join(' ')
  const platform = [m.platform?.os, m.platform?.arch].filter(Boolean).join('/')
  return (
    <DetailSection title={t('sensors.manifest.current', 'Current manifest')}>
      <DetailFieldGrid>
        <DetailField label={t('sensors.manifest.digest', 'Digest')}>
          <span className="flex flex-col gap-0.5">
            <Digest digest={v.digest} />
            <span className="text-xs text-muted-foreground" title={exactTime(v.current_since)}>
              {t('sensors.manifest.currentSince', '{source}, current since {ago}', {
                source: manifestSourceLabel(v.source, t),
                ago: agoShort(v.current_since, now),
              })}
            </span>
          </span>
        </DetailField>
        <DetailField label={t('sensors.manifest.build', 'Build')}>
          {build || sdk ? (
            <span className="flex flex-col gap-0.5">
              {build && <span>{build}</span>}
              {sdk && <span className="text-xs text-muted-foreground">{sdk}</span>}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('sensors.manifest.resources', 'Resources')}>
          {resources || platform ? (
            <span className="flex flex-col gap-0.5 tabular-nums">
              {resources && <span>{resources}</span>}
              {platform && <span className="text-xs text-muted-foreground">{platform}</span>}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('sensors.manifest.concurrency', 'Concurrency')}>
          {concurrencyText(m, t)}
        </DetailField>
        {(m.capabilities?.length ?? 0) > 0 && (
          <DetailField
            label={t('sensors.manifest.sensorWideCapabilities', 'Sensor-wide capabilities')}
            full
          >
            <span className="flex flex-wrap gap-1">
              {m.capabilities!.map((c) => (
                <SensorTag key={c}>{c}</SensorTag>
              ))}
            </span>
          </DetailField>
        )}
      </DetailFieldGrid>

      <ul
        className="divide-y rounded-lg border"
        aria-label={t('sensors.manifest.toolsAria', 'Manifest tools')}
      >
        {m.tools.length === 0 && (
          <li className="px-3 py-2 text-sm text-muted-foreground">
            {t('sensors.manifest.noTools', 'The sensor registered no tools.')}
          </li>
        )}
        {m.tools.map((tool) => (
          <li key={tool.name} data-tool={tool.name} className="space-y-1 px-3 py-2 text-sm">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className={cn('font-medium', !tool.installed && 'text-muted-foreground')}>
                {tool.name}
              </span>
              {tool.version && (
                <span className="text-xs text-muted-foreground tabular-nums">{tool.version}</span>
              )}
              {tool.kind && <SensorTag>{tool.kind}</SensorTag>}
              {!tool.installed && (
                <SensorTag tone="warning">
                  {t('sensors.manifest.notInstalled', 'not installed')}
                </SensorTag>
              )}
            </div>
            {(tool.capabilities?.length ?? 0) > 0 && (
              <div
                className="flex flex-wrap gap-1"
                aria-label={t('sensors.manifest.toolCapabilitiesAria', '{tool} capabilities', {
                  tool: tool.name,
                })}
              >
                {tool.capabilities!.map((c) => (
                  <SensorTag key={c} tone="info">
                    {c}
                  </SensorTag>
                ))}
              </div>
            )}
            {(tool.content?.length ?? 0) > 0 && (
              <div className="text-xs text-muted-foreground">
                {tool.content!.map((c) => [c.name, c.version].filter(Boolean).join(' ')).join(', ')}
              </div>
            )}
            {tool.contract && <ToolContract tool={tool.name} c={tool.contract} />}
            {tool.contract?.descriptor != null && (
              <SensorToolOptions tool={tool.name} descriptor={tool.contract.descriptor} />
            )}
          </li>
        ))}
      </ul>

      {v.ignored.length > 0 && (
        <div
          className="space-y-1 rounded-lg border border-warning/40 bg-warning/5 px-3 py-2 text-sm"
          role="note"
        >
          <p className="flex items-center gap-1.5 font-medium">
            <AlertTriangle className="h-3.5 w-3.5 text-warning" aria-hidden />
            {v.ignored.length === 1
              ? t('sensors.manifest.ignoredOne', 'The platform ignored 1 item')
              : t('sensors.manifest.ignoredMany', 'The platform ignored {n} items', {
                  n: v.ignored.length,
                })}
          </p>
          <p className="text-xs text-muted-foreground">
            {ignoredLooksNewer(v.ignored)
              ? t(
                  'sensors.manifest.ignoredNewer',
                  'This sensor is newer than the platform; these items will be used after the platform is updated.'
                )
              : t(
                  'sensors.manifest.ignoredInvalid',
                  'Some of these items are invalid; a sensor update will not change that.'
                )}
          </p>
          <ul className="text-xs text-muted-foreground">
            {v.ignored.map((i) => (
              <li key={`${i.path}:${i.value ?? ''}`}>
                <span className="font-mono">{i.path}</span>
                {i.value ? ` "${i.value}"` : ''}: {ignoredReasonLabel(i.reason, t)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </DetailSection>
  )
}

function History({ versions, now }: { versions: SensorManifestVersion[]; now: number }) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const rows = manifestHistory(versions)
  const shown = all ? rows : rows.slice(0, HISTORY_PREVIEW)
  return (
    <DetailSection title={t('sensors.manifest.history', 'History')} count={versions.length}>
      <ol
        className="space-y-3"
        aria-label={t('sensors.manifest.versionsAria', 'Manifest versions')}
      >
        {shown.map(({ version: v, diff }) => {
          const lines = diff && !isEmptyDiff(diff) ? manifestDiffLines(diff, t) : []
          return (
            <li key={v.digest} className="space-y-1 border-s-2 ps-3 text-sm">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span title={exactTime(v.current_since)}>{agoShort(v.current_since, now)}</span>
                <Digest digest={v.digest} />
                <SensorTag>
                  {v.source === 'sensor'
                    ? t('sensors.manifest.registered', 'registered')
                    : t('sensors.manifest.derived', 'derived')}
                </SensorTag>
                {v.current && (
                  <SensorTag tone="success">
                    {t('sensors.manifest.currentTag', 'current')}
                  </SensorTag>
                )}
              </div>
              {diff === null ? (
                <p className="text-xs text-muted-foreground">
                  {t('sensors.manifest.firstVersion', 'First version kept.')}
                </p>
              ) : lines.length > 0 ? (
                <ul className="text-xs text-muted-foreground">
                  {lines.map((l) => (
                    <li key={l}>{l}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {t('sensors.manifest.contentOnly', 'Content versions only.')}
                </p>
              )}
            </li>
          )
        })}
      </ol>
      {rows.length > HISTORY_PREVIEW && (
        <Button variant="ghost" size="sm" onClick={() => setAll((a) => !a)}>
          {all
            ? t('sensors.manifest.showFewer', 'Show fewer')
            : t('sensors.manifest.showAll', 'Show all {n}', { n: rows.length })}
        </Button>
      )}
    </DetailSection>
  )
}

/**
 * The drawer's Manifest tab (api RFC-033): what the sensor is, as it
 * registered it or as the platform derived it from its heartbeat, and the
 * history of versions with what changed between them.
 */
export function SensorManifestTab({ sensor, now }: { sensor: Sensor; now: number }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSensorManifests(sensor.id)
  const versions = data?.items ?? []
  const current = versions.find((v) => v.current) ?? null

  if (isLoading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }
  if (error) {
    return (
      <div className="space-y-2 text-sm" role="alert">
        <p>{t('sensors.manifest.loadError', 'The manifest could not be loaded.')}</p>
        <Button variant="outline" size="sm" onClick={() => mutate()}>
          {t('sensors.manifest.retry', 'Retry')}
        </Button>
      </div>
    )
  }
  if (!current) {
    return (
      <p className="text-sm text-muted-foreground">
        {t(
          'sensors.manifest.empty',
          'No manifest yet. A sensor registers one when it connects, and the platform derives one from the first heartbeat that reports its tools.'
        )}
      </p>
    )
  }
  return (
    <DetailSections>
      <CurrentManifest v={current} now={now} />
      <History versions={versions} now={now} />
    </DetailSections>
  )
}
