/**
 * The dashboard surfaces are fully translated (research 203, P0-9): every
 * message key they use exists in English and Vietnamese, every catalog
 * metric, dimension value, visualization, range, schedule and template has
 * its names, Vietnamese text is not a copy of the English, no display text is
 * hard-coded in the components, and a dashboard rendered in Vietnamese shows
 * no English message.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import en from '@/lib/i18n/dictionaries/en/dashboards.json'
import vi_ from '@/lib/i18n/dictionaries/vi/dashboards.json'
import enKit from '@/lib/i18n/dictionaries/en/dashboardKit.json'
import viKit from '@/lib/i18n/dictionaries/vi/dashboardKit.json'
import { SCHEDULE_OPTIONS } from '../components/dashboard-freshness'
import { DashboardView } from '../components/dashboard-view'
import {
  METRIC_GROUPS,
  METRICS,
  dimensionValueKey,
  metricDefinitionKey,
  metricNameKey,
} from '../metrics'
import {
  DASHBOARD_TEMPLATES,
  templateDescriptionKey,
  templateLayout,
  templateNameKey,
} from '../templates'
import type { DashboardData, WidgetValue } from '../api/widget-data'
import type { Dimension, VizType } from '../api/widget-spec'

vi.mock('@/components/charts', async (orig) => orig())

const SRC = join(process.cwd(), 'src')
const SURFACES = [
  'features/dashboards',
  'components/dashboard-kit',
  'app/(dashboard)/page.tsx',
  'app/(dashboard)/dashboards/page.tsx',
]

function files(rel: string): string[] {
  const abs = join(SRC, rel)
  if (statSync(abs).isFile()) return [rel]
  return readdirSync(abs).flatMap((f) => {
    const r = join(rel, f)
    if (f === '__tests__') return []
    return statSync(join(SRC, r)).isDirectory() ? files(r) : /\.tsx?$/.test(f) ? [r] : []
  })
}
const sources = SURFACES.flatMap(files).map((f) => ({
  f,
  text: readFileSync(join(SRC, f), 'utf8'),
}))

const EN = { ...en, ...enKit } as Record<string, string>
const VI = { ...vi_, ...viKit } as Record<string, string>

// Values that read the same in both languages.
const SAME_IN_BOTH = new Set(['P0', 'P1', 'P2', 'P3', 'widget', 'KEV'])

const VIZZES: VizType[] = [
  'stat',
  'progress',
  'bar',
  'column',
  'area',
  'line',
  'diverging',
  'table',
  'heatmap',
  'list',
  'donut',
  'note',
]
const RANGES = ['inherit', '7d', '30d', '90d', '365d']
const COMPARES = ['none', 'previous_period']
const DIMENSION_VALUES: Partial<Record<Dimension, string[]>> = {
  severity: ['critical', 'high', 'medium', 'low', 'info', 'none'],
  priority_class: ['P0', 'P1', 'P2', 'P3', 'none'],
  sla_state: ['ok', 'warning', 'breached', 'none'],
  age_band: ['0-30', '31-60', '61-90', '90+', 'na'],
  kev: ['true', 'false'],
  reachable: ['true', 'false'],
}
const REASONS = [
  'no_denominator',
  'too_few_fixed',
  'legacy_tile',
  'forbidden',
  'facts_building',
  'timeout',
  'empty',
  'pending',
  'failed',
]

function dynamicKeys(): string[] {
  const keys: string[] = []
  for (const m of METRICS) keys.push(metricNameKey(m.id), metricDefinitionKey(m.id))
  for (const g of METRIC_GROUPS) keys.push(`dashboards.group.${g}`)
  for (const v of VIZZES) keys.push(`dashboards.viz.${v}`)
  for (const r of RANGES) keys.push(`dashboards.range.${r}`)
  for (const c of COMPARES) keys.push(`dashboards.compare.${c}`)
  for (const s of SCHEDULE_OPTIONS) if (s) keys.push(`dashboards.schedule.${s}`)
  for (const [dim, values] of Object.entries(DIMENSION_VALUES)) {
    keys.push(`dashboards.dimension.${dim}.name`)
    for (const v of values ?? []) keys.push(dimensionValueKey(dim as Dimension, v))
  }
  for (const r of REASONS) keys.push(`dashboards.reason.${r}`)
  for (const f of ['opened', 'fixed']) keys.push(`dashboards.flow.${f}`)
  for (const tpl of DASHBOARD_TEMPLATES)
    keys.push(templateNameKey(tpl.key), templateDescriptionKey(tpl.key))
  return keys
}

describe('dashboard i18n completeness', () => {
  it('every statically used key exists in English and Vietnamese', () => {
    const missing: string[] = []
    for (const { f, text } of sources) {
      for (const m of text.matchAll(/\bt\(\s*['"`]((?:dashboards|dashboardKit)\.[\w.-]+)['"`]/g)) {
        if (!(m[1] in EN) || !(m[1] in VI)) missing.push(`${f}: ${m[1]}`)
      }
    }
    expect(missing).toEqual([])
  })

  it('every metric, dimension value, visualization, range, schedule, reason and template is named', () => {
    const missing = dynamicKeys().filter((k) => !(k in EN) || !(k in VI))
    expect(missing).toEqual([])
  })

  it('every template uses only metrics the web can name', () => {
    const known = new Set(METRICS.map((m) => m.id))
    for (const tpl of DASHBOARD_TEMPLATES) {
      for (const w of tpl.widgets) {
        const metric = (w.config as { data?: { metric?: string } }).data?.metric
        if (metric) expect(known.has(metric), `${tpl.key}: ${metric}`).toBe(true)
      }
    }
  })

  it('Vietnamese text is not a copy of the English', () => {
    const copies = Object.keys(EN).filter(
      (k) => VI[k] === EN[k] && !SAME_IN_BOTH.has(EN[k]) && /[a-z]{3,}/.test(EN[k])
    )
    expect(copies).toEqual([])
  })

  it('no display text is hard-coded in the dashboard components', () => {
    const found: string[] = []
    for (const { f, text } of sources) {
      if (!f.endsWith('.tsx')) continue
      // JSX text before a closing tag with at least one word of three letters.
      for (const m of text.matchAll(
        />\s*([A-Za-z][A-Za-z ,.'!?-]*[a-z]{3,}[A-Za-z ,.'!?-]*)\s*<\//g
      )) {
        found.push(`${f}: >${m[1].trim()}<`)
      }
      // Literal user-facing attributes.
      for (const m of text.matchAll(
        /\b(aria-label|placeholder|title|alt)="([^"{]*[a-z]{3,}[^"]*)"/g
      )) {
        found.push(`${f}: ${m[1]}="${m[2]}"`)
      }
    }
    expect(found).toEqual([])
  })

  it('every template rendered in Vietnamese shows no English message', () => {
    // English values that differ from their Vietnamese text: seeing one
    // means a key fell back to English.
    const englishOnly = new Set(
      Object.keys(EN)
        .filter((k) => VI[k] && VI[k] !== EN[k] && !EN[k].includes('{'))
        .map((k) => EN[k])
    )
    for (const tpl of DASHBOARD_TEMPLATES) {
      const layout = templateLayout(tpl)
      const values: WidgetValue[] = layout.map((w, i) => ({
        id: (w.config as { id: string }).id,
        index: i,
        widget_type: 'metric',
        state: 'not_measured',
        reason: 'too_few_fixed',
        metric: (w.config as { data: { metric: string } }).data.metric,
      }))
      const data: DashboardData = {
        dashboard_id: tpl.key,
        scope: 'personal',
        restricted: true,
        facts_built_at: '2026-10-21T00:00:00Z',
        computed_at: new Date().toISOString(),
        stale: false,
        widgets: values,
      }
      const { container, unmount } = render(
        <I18nProvider locale="vi">
          <DashboardView dashboard={{ layout, columns: tpl.columns }} data={data} loading={false} />
        </I18nProvider>
      )
      const texts = Array.from(container.querySelectorAll('*'))
        .flatMap((el) => Array.from(el.childNodes))
        .filter((n) => n.nodeType === 3)
        .map((n) => (n.textContent ?? '').trim())
        .filter(Boolean)
      const english = texts.filter((s) => englishOnly.has(s))
      expect(english, tpl.key).toEqual([])
      unmount()
    }
  })
})
