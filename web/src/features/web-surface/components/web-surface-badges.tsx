'use client'

import Link from '@/components/link'
import { ShieldOff } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { TonePill, type PillTone } from '@/features/shared'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import type { WebPathCatalogEntry } from '@/lib/api/generated'

/** An HTTP method as a fixed-width mono label; write methods stand out. */
export function MethodBadge({ method }: { method?: string }) {
  const m = (method ?? 'ANY').toUpperCase()
  const write = m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE'
  return (
    <span
      className={cn(
        'inline-flex min-w-[3.25rem] justify-center rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold',
        write ? 'bg-warning/15 text-warning' : 'bg-muted text-muted-foreground'
      )}
    >
      {m}
    </span>
  )
}

/**
 * A path template or an example path: scan output, rendered as text, never as
 * a link that fetches it.
 */
export function PathText({ path, className }: { path?: string; className?: string }) {
  return (
    <span className={cn('font-mono text-sm break-all', className)} title={path}>
      {path || '/'}
    </span>
  )
}

const AUTH_TONE: Record<string, PillTone> = {
  none: 'warning',
  required: 'success',
  redirect_login: 'success',
  unknown: 'muted',
}

export function AuthPill({ state }: { state?: string }) {
  const { t } = useTranslation()
  const key = state && state in AUTH_TONE ? state : 'unknown'
  const labels: Record<string, string> = {
    none: t('attackSurface.web.auth.none', 'No auth'),
    required: t('attackSurface.web.auth.required', 'Auth required'),
    redirect_login: t('attackSurface.web.auth.redirect_login', 'Login redirect'),
    unknown: t('attackSurface.web.auth.unknown', 'Unknown'),
  }
  return <TonePill tone={AUTH_TONE[key]} label={labels[key]} />
}

const SEVERITY_TONE: Record<string, PillTone> = {
  critical: 'destructive',
  high: 'destructive',
  medium: 'warning',
  low: 'info',
  info: 'muted',
}

/** A sensitive-path catalog match: its title, toned by how bad exposure is. */
export function CatalogBadge({ entry }: { entry?: WebPathCatalogEntry }) {
  const { t } = useTranslation()
  if (!entry?.key) return null
  return (
    <TonePill
      tone={SEVERITY_TONE[entry.severity ?? ''] ?? 'muted'}
      label={entry.title ?? entry.key}
      title={t('attackSurface.web.catalog.title', 'Sensitive path ({category}, {severity})', {
        category: entry.category ?? 'catalog',
        severity: entry.severity ?? 'unknown',
      })}
    />
  )
}

/**
 * "Excluded, untested": the endpoint lies under a scope exclusion, so no scan
 * ever sent anything there. It links to the exclusion (where an approver can
 * set its testing mode); absence of findings here is not evidence of safety.
 */
export function ExcludedBadge({ exclusionId }: { exclusionId?: string }) {
  const { t } = useTranslation()
  const badge = (
    <Badge variant="outline" className="gap-1 border-warning/50 font-normal text-warning">
      <ShieldOff className="h-3 w-3" aria-hidden />
      {t('attackSurface.originWeb.metric.untested', 'Excluded, untested')}
    </Badge>
  )
  if (!exclusionId) return badge
  return (
    <Link
      href="/scope?tab=exclusions"
      className="inline-flex"
      aria-label={t(
        'attackSurface.web.excludedOpen',
        'Excluded, untested: open the scope exclusions'
      )}
    >
      {badge}
    </Link>
  )
}
