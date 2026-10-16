/**
 * A sample render of a mapping template, for the editor's live render. It
 * mirrors the API's template language (pkg/domain/ticketmap/template.go) on
 * sample values; the Preview tab renders real objects through the API, which
 * is the only renderer that reaches a tracker.
 */

import type { CatalogAttribute } from '../types/ticket-mapping.types'

const SAMPLE_BY_PATH: Record<string, string | string[]> = {
  'finding.title': 'SQL injection in /search',
  'finding.severity': 'high',
  'finding.priority_class': 'P1',
  'finding.cve_ids': ['CVE-2026-1234'],
  'finding.cwe_ids': ['CWE-89'],
  'finding.asset_name': 'api-payments',
  'finding.location': 'src/search.go:42',
  'finding.file_path': 'src/search.go',
  'finding.tool': 'semgrep',
  'finding.source': 'sast',
  'finding.url': 'https://openctem.example/findings/…',
  'task.title': 'Upgrade django to 4.2.30',
  'task.url': 'https://openctem.example/remediation/…',
  'task.priority': 'high',
  'task.finding_count': '12',
}

function sampleFor(attr: CatalogAttribute | undefined): string | string[] {
  if (!attr) return ''
  if (SAMPLE_BY_PATH[attr.path] !== undefined) return SAMPLE_BY_PATH[attr.path]
  switch (attr.type) {
    case 'number':
      return '7.5'
    case 'date':
      return '2026-10-22'
    case 'bool':
      return 'yes'
    case 'list':
      return ['a', 'b']
    case 'enum':
      return attr.enum?.[0] ?? ''
    case 'user':
      return 'Hoa N.'
  }
  return attr.path.split('.').pop() ?? ''
}

const truncate = (s: string, n: number) => {
  const r = Array.from(s)
  if (r.length <= n) return s
  return n <= 1 ? r.slice(0, n).join('') : r.slice(0, n - 1).join('') + '…'
}

function unquote(a: string): string {
  const t = a.trim()
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"'))
    return t.slice(1, -1).replace(/\\"/g, '"')
  return t
}

function splitPipes(expr: string): string[] {
  const out: string[] = []
  let cur = ''
  let inQ = false
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i]
    if (c === '"' && expr[i - 1] !== '\\') inQ = !inQ
    if (c === '|' && !inQ) {
      out.push(cur)
      cur = ''
    } else cur += c
  }
  out.push(cur)
  return out
}

export interface SampleRender {
  text: string
  errors: string[]
}

/** Renders a template over sample values; reports unknown paths and filters. */
export function renderSample(
  template: string,
  attrs: CatalogAttribute[],
  filters: string[]
): SampleRender {
  const byPath = new Map(attrs.map((a) => [a.path, a]))
  const errors: string[] = []
  const text = template.replace(/\{\{([^}]*)\}\}/g, (_m, expr: string) => {
    const segs = splitPipes(expr)
    const path = segs[0].trim()
    const attr = byPath.get(path)
    if (!attr) {
      errors.push(path)
      return ''
    }
    let v: string | string[] = sampleFor(attr)
    for (const seg of segs.slice(1)) {
      const s = seg.trim()
      const k = s.indexOf(':')
      const name = (k >= 0 ? s.slice(0, k) : s).trim()
      const arg = k >= 0 ? unquote(s.slice(k + 1)) : ''
      if (!filters.includes(name)) {
        errors.push(name)
        continue
      }
      const str = Array.isArray(v) ? v.join(', ') : v
      switch (name) {
        case 'join':
          v = Array.isArray(v) ? v.join(arg || ', ') : v
          break
        case 'first':
          v = Array.isArray(v) ? (v[0] ?? '') : v
          break
        case 'count':
          v = String(Array.isArray(v) ? v.length : v ? 1 : 0)
          break
        case 'truncate':
          v = truncate(str, Number(arg) || 1)
          break
        case 'default':
          v = str === '' ? arg : v
          break
        case 'upper':
          v = str.toUpperCase()
          break
        case 'lower':
          v = str.toLowerCase()
          break
        case 'date':
          v = str
          break
      }
    }
    return Array.isArray(v) ? v.join(', ') : v
  })
  return { text, errors }
}
