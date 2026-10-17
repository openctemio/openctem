/** Display helpers shared by the organization and console support-access views. */

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** A timestamp in the viewer's locale with the time ("16 Oct 2026, 14:05"). */
export function formatSupportTime(value: string | undefined | null, locale: string): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  try {
    return d.toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' })
  } catch {
    return d.toISOString()
  }
}

/** "findings and assets" in the viewer's language; unknown scopes pass through. */
export function formatSupportScopes(scopes: string[] | undefined, t: Translate): string {
  const labels = (scopes ?? []).map((s) => {
    if (s === 'findings') return t('supportAccess.scope.findings', 'findings')
    if (s === 'assets') return t('supportAccess.scope.assets', 'assets')
    return s
  })
  if (labels.length <= 1) return labels[0] ?? ''
  return t('supportAccess.scope.join', '{first} and {second}', {
    first: labels.slice(0, -1).join(', '),
    second: labels[labels.length - 1],
  })
}
