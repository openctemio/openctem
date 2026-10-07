'use client'

import Link from 'next/link'
import { ShieldOff } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { TonePill, type PillTone } from '@/features/shared'
import { cn } from '@/lib/utils'
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

const AUTH: Record<string, { label: string; tone: PillTone }> = {
  none: { label: 'No auth', tone: 'warning' },
  required: { label: 'Auth required', tone: 'success' },
  redirect_login: { label: 'Login redirect', tone: 'success' },
  unknown: { label: 'Unknown', tone: 'muted' },
}

export function AuthPill({ state }: { state?: string }) {
  const a = AUTH[state ?? 'unknown'] ?? AUTH.unknown
  return <TonePill tone={a.tone} label={a.label} />
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
  if (!entry?.key) return null
  return (
    <TonePill
      tone={SEVERITY_TONE[entry.severity ?? ''] ?? 'muted'}
      label={entry.title ?? entry.key}
      title={`Sensitive path (${entry.category ?? 'catalog'}, ${entry.severity ?? 'unknown'})`}
    />
  )
}

/**
 * "Excluded, untested": the endpoint lies under a scope exclusion, so no scan
 * ever sent anything there. It links to the exclusion (where an approver can
 * set its testing mode); absence of findings here is not evidence of safety.
 */
export function ExcludedBadge({ exclusionId }: { exclusionId?: string }) {
  const badge = (
    <Badge variant="outline" className="gap-1 border-warning/50 font-normal text-warning">
      <ShieldOff className="h-3 w-3" aria-hidden />
      Excluded, untested
    </Badge>
  )
  if (!exclusionId) return badge
  return (
    <Link
      href="/scope-config?tab=exclusions"
      className="inline-flex"
      aria-label="Excluded, untested: open the scope exclusions"
    >
      {badge}
    </Link>
  )
}
