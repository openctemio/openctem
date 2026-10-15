'use client'

/**
 * What a role can do, in words (api RFC-095 §2.5): a risk tier with the
 * reasons, and the product areas it views or changes. Shown wherever a role
 * is picked or listed, instead of a bare permission count.
 */
import { ShieldAlert, ShieldCheck, ShieldHalf, Shield } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

import type { RoleRisk, RoleSummary } from '../types/role.types'

const RISK_STYLE: Record<RoleRisk, string> = {
  low: 'border-border text-muted-foreground',
  medium: 'border-primary/30 text-primary',
  high: 'border-warning/50 bg-warning/10 text-warning',
  critical: 'border-destructive/50 bg-destructive/10 text-destructive',
}

const RISK_ICON: Record<RoleRisk, typeof Shield> = {
  low: ShieldCheck,
  medium: Shield,
  high: ShieldHalf,
  critical: ShieldAlert,
}

/** Areas known to the dictionaries; anything else is shown humanized. */
const KNOWN_AREAS = new Set([
  'ai_triage',
  'assets',
  'attack_surface',
  'audit',
  'compliance',
  'ctem',
  'dashboard',
  'findings',
  'integrations',
  'pentest',
  'reports',
  'scans',
  'sensors',
  'settings',
  'team',
  'threat_intel',
  'validation',
])

const KNOWN_REASONS = new Set([
  'admin',
  'full_data',
  'manage_people',
  'secrets',
  'api_keys',
  'settings',
  'approve',
  'run_scans',
  'delete',
])

function humanize(id: string): string {
  const s = id.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export function useRoleWords() {
  const { t } = useTranslation()
  return {
    risk: (r: RoleRisk) => t(`org.roleRisk.${r}`),
    area: (a: string) => (KNOWN_AREAS.has(a) ? t(`org.roleArea.${a}`) : humanize(a)),
    reason: (r: string) => (KNOWN_REASONS.has(r) ? t(`org.roleReason.${r}`) : humanize(r)),
  }
}

export function RoleRiskBadge({ risk, className }: { risk: RoleRisk; className?: string }) {
  const words = useRoleWords()
  const Icon = RISK_ICON[risk]
  return (
    <Badge
      variant="outline"
      className={cn('gap-1 px-1.5 py-0 text-[11px] font-medium', RISK_STYLE[risk], className)}
      data-testid={`role-risk-${risk}`}
    >
      <Icon className="size-3" aria-hidden="true" />
      {words.risk(risk)}
    </Badge>
  )
}

/**
 * One line under a role's name: why it is risky (when it is) and the areas it
 * changes, then those it only views. `max` caps the areas shown.
 */
export function RoleSummaryLine({
  summary,
  max = 4,
  className,
  id,
}: {
  summary: RoleSummary | undefined
  max?: number
  className?: string
  id?: string
}) {
  const { t } = useTranslation()
  const words = useRoleWords()
  if (!summary) return null
  const reasons = summary.reasons.slice(0, 2).map(words.reason)
  const changes = summary.areas.filter((a) => a.level === 'change').map((a) => words.area(a.area))
  const views = summary.areas.filter((a) => a.level === 'view').map((a) => words.area(a.area))
  const parts: string[] = []
  if (reasons.length > 0) parts.push(reasons.join(', '))
  if (changes.length > 0) {
    const shown = changes.slice(0, max)
    const more = changes.length - shown.length
    parts.push(
      t('org.roleSummary.changes', undefined, { areas: shown.join(', ') }) +
        (more > 0 ? ` ${t('org.roleSummary.more', undefined, { count: more })}` : '')
    )
  } else if (views.length > 0) {
    const shown = views.slice(0, max)
    const more = views.length - shown.length
    parts.push(
      t('org.roleSummary.views', undefined, { areas: shown.join(', ') }) +
        (more > 0 ? ` ${t('org.roleSummary.more', undefined, { count: more })}` : '')
    )
  }
  if (parts.length === 0) return null
  const line = parts.join(' · ')
  return (
    <p id={id} className={cn('text-xs text-muted-foreground', className)}>
      {line.charAt(0).toUpperCase() + line.slice(1)}
    </p>
  )
}
