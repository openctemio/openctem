'use client'

import { useMemo } from 'react'
import Link from '@/components/link'
import { History } from 'lucide-react'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useHasPermission, Permission } from '@/lib/permissions'
import { useResourceAuditHistory } from '../api/use-audit-logs'
import type { AuditLog } from '../types/audit.types'

/** Field names a change touched: the keys of its before/after maps. */
export function changedFields(log: Pick<AuditLog, 'changes'>): string[] {
  const c = (log.changes ?? {}) as {
    before?: Record<string, unknown>
    after?: Record<string, unknown>
  }
  return [...new Set([...Object.keys(c.before ?? {}), ...Object.keys(c.after ?? {})])]
}

/** The newest change among `logs` that touched one of `fields` (dotted keys match by prefix). */
export function lastChangeOf(
  logs: readonly AuditLog[],
  fields: readonly string[]
): AuditLog | undefined {
  return logs.find((log) =>
    changedFields(log).some((k) => fields.some((f) => k === f || k.startsWith(`${f}.`)))
  )
}

/**
 * "Last changed by Olivia · 2 days ago" for a group of settings, read from the
 * resource's audit history (GET /audit-logs/resource/{type}/{id}; needs
 * audit:read, so it shows nothing for anyone else). Links to the audit log.
 */
export function LastChanged({
  resourceType,
  resourceId,
  fields,
}: {
  resourceType: string
  resourceId: string | undefined
  fields: readonly string[]
}) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.AuditRead)
  const { logs } = useResourceAuditHistory(canRead ? resourceType : undefined, resourceId, 1, 50)
  const last = useMemo(() => lastChangeOf(logs ?? [], fields), [logs, fields])
  if (!last) return null
  return (
    <p className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
      <History className="size-3.5" aria-hidden />
      <span>
        {t('org.lastChanged.by', 'Last changed by {actor}', {
          actor: last.actor_email || t('org.lastChanged.system', 'the system'),
        })}
      </span>
      <span aria-hidden>·</span>
      <RelativeTime date={last.timestamp} />
      <span aria-hidden>·</span>
      <Link href="/settings/audit-log" className="underline-offset-2 hover:underline">
        {t('org.lastChanged.history', 'History')}
      </Link>
    </p>
  )
}
