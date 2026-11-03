'use client'

/**
 * The sources of a connected visual (the exposure flow and the intake panel;
 * api docs/architecture/dashboards.md, "Exposure flow and intake"): their
 * words (name, kind, health), the regrouping by instance, the viewer's view
 * (rank by findings or assets, group by tool or instance, remembered on this
 * browser and shared by both widgets), its switchers, and the ranked rows
 * both widgets draw with RankedBars. One source reads the same everywhere.
 */

import { useCallback, useEffect, useState } from 'react'
import { Radio, Server, ShieldAlert, Wrench } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { ViewSwitcher } from '@/features/shared/components/view-switcher'
import { formatCount, formatRelativeTime } from '@/lib/format-metric'
import { toDisplayText } from '@/lib/untrusted-text'
import { tCount } from './flow-parts'
import type { RankedBarRow } from './ranked-bars'
import type { IntakeInstance, IntakeSourceRow, SourceHealth } from './types'

/** Where the viewer's source view (measure, grouping) is remembered. */
const SOURCE_VIEW_KEY = 'openctem.dashboard.flow.sources'

export type Translate = ReturnType<typeof useTranslation>['t']
export type Measure = 'findings' | 'assets'
export type Grouping = 'tool' | 'instance'

/** The words of a source group. */
export function originLabel(t: Translate, origin: string): string {
  switch (origin) {
    case 'sensor':
      return t('dashboardKit.flow.origin.sensor', 'Sensor')
    case 'import':
      return t('dashboardKit.flow.origin.import', 'Import')
    case 'connector':
      return t('dashboardKit.flow.origin.connector', 'Connector')
    case 'ci':
      return t('dashboardKit.flow.origin.ci', 'CI')
    case 'platform':
      return t('dashboardKit.flow.origin.platform', 'Platform')
    default:
      return origin
  }
}

/** The name of a source: its tool, or "Unnamed tool". */
export function sourceName(t: Translate, s: IntakeSourceRow): string {
  return s.tool === 'unknown' || !s.tool
    ? t('dashboardKit.flow.unnamedTool', 'Unnamed tool')
    : toDisplayText(s.tool, 80)
}

/** "Stale, last receipt 3 days ago" / "Failed 2 hours ago", or null when healthy. */
export function healthNote(
  t: Translate,
  s: { health: SourceHealth; last_at: string | null },
  locale: string
): string | null {
  if (s.health === 'ok') return null
  const when = formatRelativeTime(s.last_at, locale)
  return s.health === 'failed'
    ? t('dashboardKit.flow.health.failed', 'Failed {when}', { when })
    : t('dashboardKit.flow.health.stale', 'Stale, last receipt {when}', { when })
}

const HEALTH_RANK: Record<SourceHealth, number> = { ok: 0, stale: 1, failed: 2 }

/** The worst of two healths. */
function worst(a: SourceHealth, b: SourceHealth): SourceHealth {
  return HEALTH_RANK[b] > HEALTH_RANK[a] ? b : a
}

/** One instance with what it fed, summed over the tools it reported for. */
export interface InstanceGroup {
  key: string
  instance: IntakeInstance
  received: number
  assets: number
  health: SourceHealth
  last_at: string | null
  tools: Array<{ name: string; received: number; assets: number }>
}

/** The sources regrouped by instance (sensor, CI project, connector, platform). */
export function groupByInstance(t: Translate, sources: IntakeSourceRow[]): InstanceGroup[] {
  const out = new Map<string, InstanceGroup>()
  for (const s of sources) {
    for (const i of s.instances ?? []) {
      const key = `${i.kind}:${i.id}`
      const g = out.get(key) ?? {
        key,
        instance: i,
        received: 0,
        assets: 0,
        health: 'ok' as SourceHealth,
        last_at: null as string | null,
        tools: [],
      }
      g.received += i.received
      g.assets += i.assets ?? 0
      g.health = worst(g.health, i.health)
      if (i.last_at && (!g.last_at || i.last_at > g.last_at)) g.last_at = i.last_at
      g.tools.push({ name: sourceName(t, s), received: i.received, assets: i.assets ?? 0 })
      out.set(key, g)
    }
  }
  return [...out.values()]
}

function readSourceView(): { measure?: Measure; group?: Grouping } {
  try {
    const raw = window.localStorage.getItem(SOURCE_VIEW_KEY)
    if (!raw) return {}
    const v = JSON.parse(raw) as { measure?: unknown; group?: unknown }
    return {
      measure: v.measure === 'assets' || v.measure === 'findings' ? v.measure : undefined,
      group: v.group === 'instance' || v.group === 'tool' ? v.group : undefined,
    }
  } catch {
    return {}
  }
}

function writeSourceView(v: { measure: Measure; group: Grouping }) {
  try {
    window.localStorage.setItem(SOURCE_VIEW_KEY, JSON.stringify(v))
  } catch {
    // Private mode or blocked storage: the view is not remembered.
  }
}

/** The viewer's source view, remembered on this browser. */
export function useSourceView(): [Measure, Grouping, (m: Measure) => void, (g: Grouping) => void] {
  const [measure, setMeasure] = useState<Measure>('findings')
  const [group, setGroup] = useState<Grouping>('tool')
  useEffect(() => {
    const v = readSourceView()
    if (v.measure) setMeasure(v.measure)
    if (v.group) setGroup(v.group)
  }, [])
  const pickMeasure = useCallback(
    (m: Measure) => {
      setMeasure(m)
      writeSourceView({ measure: m, group })
    },
    [group]
  )
  const pickGroup = useCallback(
    (g: Grouping) => {
      setGroup(g)
      writeSourceView({ measure, group: g })
    },
    [measure]
  )
  return [measure, group, pickMeasure, pickGroup]
}

/** Which view a set of sources supports: the asset measure and the instance grouping need data. */
export function sourceViewFor(
  sources: IntakeSourceRow[],
  measure: Measure,
  group: Grouping
): { m: Measure; g: Grouping; hasAssets: boolean; hasInstances: boolean } {
  const hasAssets = sources.some((s) => (s.assets ?? 0) > 0)
  const hasInstances = sources.some((s) => (s.instances?.length ?? 0) > 0)
  return {
    m: hasAssets ? measure : 'findings',
    g: hasInstances ? group : 'tool',
    hasAssets,
    hasInstances,
  }
}

/** The switchers of the source view: rank by findings or assets, group by tool or instance. */
export function SourceViewSwitchers({
  m,
  g,
  hasAssets,
  hasInstances,
  setMeasure,
  setGroup,
}: {
  m: Measure
  g: Grouping
  hasAssets: boolean
  hasInstances: boolean
  setMeasure: (m: Measure) => void
  setGroup: (g: Grouping) => void
}) {
  const { t } = useTranslation()
  if (!hasAssets && !hasInstances) return null
  return (
    <div className="flex flex-wrap gap-2">
      {hasAssets && (
        <ViewSwitcher
          value={m}
          onChange={setMeasure}
          options={[
            {
              value: 'findings',
              label: t('dashboardKit.flow.measure.findings', 'Findings'),
              icon: ShieldAlert,
            },
            {
              value: 'assets',
              label: t('dashboardKit.flow.measure.assets', 'Assets'),
              icon: Server,
            },
          ]}
        />
      )}
      {hasInstances && (
        <ViewSwitcher
          value={g}
          onChange={setGroup}
          options={[
            { value: 'tool', label: t('dashboardKit.flow.group.tool', 'Tool'), icon: Wrench },
            {
              value: 'instance',
              label: t('dashboardKit.flow.group.instance', 'Source instance'),
              icon: Radio,
            },
          ]}
        />
      )}
    </div>
  )
}

/**
 * The ranked rows of a source view. By tool: one row per source (name, kind
 * chip). By instance: one row per sensor, CI project, connector or the
 * platform, the tools it ran listed under its name (the hierarchy instance
 * then tools). A discovery source with assets but no findings shows its
 * assets ("1,180 assets") instead of a bare 0, and is never folded away as a
 * source with nothing.
 */
export function sourceRankRows(
  t: Translate,
  locale: string,
  opts: {
    sources: IntakeSourceRow[]
    instances: InstanceGroup[]
    m: Measure
    g: Grouping
    color?: (s: IntakeSourceRow) => string | undefined
  }
): RankedBarRow[] {
  const n = (v: number) => formatCount(v, locale)
  const { m } = opts
  const unit = (count: number, which: Measure = m) =>
    which === 'assets'
      ? tCount(t, 'dashboardKit.flow.unit.assets', '{count} assets', '{count} asset', count, {
          count: n(count),
        })
      : tCount(t, 'dashboardKit.flow.unit.findings', '{count} findings', '{count} finding', count, {
          count: n(count),
        })
  // Findings view, nothing found, assets discovered: say so instead of 0.
  const alt = (received: number, assets: number) =>
    m === 'findings' && received === 0 && assets > 0 ? unit(assets, 'assets') : undefined
  if (opts.g === 'instance') {
    return opts.instances.map((gr) => {
      const value = m === 'assets' ? gr.assets : gr.received
      return {
        key: `i:${gr.key}`,
        label: toDisplayText(gr.instance.name, 80),
        chip: originLabel(t, gr.instance.kind),
        value,
        display: n(value),
        href: gr.instance.sensor_href ?? null,
        health: gr.health,
        note: healthNote(t, gr, locale),
        unit: unit(value),
        meta: gr.tools.map((x) => x.name).join(', '),
        alt: alt(gr.received, gr.assets),
        tie: gr.assets,
      }
    })
  }
  return opts.sources.map((s) => {
    const value = m === 'assets' ? (s.assets ?? 0) : s.received
    return {
      key: `s:${s.id}`,
      label: sourceName(t, s),
      chip: originLabel(t, s.origin),
      value,
      display: n(value),
      href: s.drill,
      color: opts.color?.(s),
      health: s.health,
      note: healthNote(t, s, locale),
      unit: unit(value),
      alt: alt(s.received, s.assets ?? 0),
      tie: s.assets ?? 0,
    }
  })
}
