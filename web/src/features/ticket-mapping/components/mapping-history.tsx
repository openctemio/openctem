'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { History, RotateCcw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { RelativeTime } from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { invalidateMappings, mappingApi, useMappingVersions } from '../api/use-ticket-mapping-api'
import type { SpecChange } from '../types/ticket-mapping.types'

function short(v: unknown): string {
  if (v == null) return '—'
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.length > 140 ? `${s.slice(0, 139)}…` : s
}

/** Versions of a profile, a row-level diff between two of them, and rollback
 *  (an earlier version is copied into the draft; history is never rewritten). */
export function MappingHistory({
  profileId,
  onRolledBack,
}: {
  profileId: string
  onRolledBack: () => void
}) {
  const { t } = useTranslation()
  const { data, isLoading } = useMappingVersions(profileId)
  const versions = data?.versions ?? []
  const [from, setFrom] = useState<number | null>(null)
  const [to, setTo] = useState<number | null>(null)
  const [changes, setChanges] = useState<SpecChange[] | null>(null)

  const compare = async (a: number, b: number) => {
    try {
      const res = await mappingApi.diff(profileId, Math.min(a, b), Math.max(a, b))
      setChanges(res.changes)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('ticketMapping.history.diffFailed', 'Could not compare the versions')
        )
      )
    }
  }

  const rollback = async (v: number) => {
    try {
      await mappingApi.rollback(profileId, v)
      await invalidateMappings(profileId)
      toast.success(
        t(
          'ticketMapping.history.rolledBack',
          'Version {v} is now the draft: review and publish it',
          { v }
        )
      )
      onRolledBack()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('ticketMapping.history.rollbackFailed', 'Could not roll back'))
      )
    }
  }

  if (isLoading) return <Skeleton className="h-40 w-full" />

  return (
    <div className="grid gap-4">
      <ul className="grid gap-2">
        {versions.map((v) => (
          <li
            key={v.version}
            className="flex flex-wrap items-center justify-between gap-2 rounded-lg border p-3"
          >
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <History className="h-4 w-4 text-muted-foreground" aria-hidden />
              <span className="font-medium">v{v.version}</span>
              <Badge variant={v.state === 'published' ? 'default' : 'outline'}>
                {t(`ticketMapping.versionState.${v.state}`, v.state)}
              </Badge>
              {v.note && <span className="text-muted-foreground">{v.note}</span>}
              <RelativeTime date={v.published_at ?? v.created_at} className="text-xs" />
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant={from === v.version ? 'default' : 'outline'}
                size="sm"
                onClick={() => {
                  if (from === null || to !== null) {
                    setFrom(v.version)
                    setTo(null)
                    setChanges(null)
                  } else if (from !== v.version) {
                    setTo(v.version)
                    void compare(from, v.version)
                  }
                }}
              >
                {from !== null && to === null && from !== v.version
                  ? t('ticketMapping.history.compareWith', 'Compare with v{v}', { v: from })
                  : t('ticketMapping.history.compare', 'Compare')}
              </Button>
              {v.state !== 'draft' && (
                <Can permission={Permission.IntegrationsManage}>
                  <Button variant="outline" size="sm" onClick={() => rollback(v.version)}>
                    <RotateCcw className="me-1 h-4 w-4" aria-hidden />
                    {t('ticketMapping.history.rollback', 'Use as draft')}
                  </Button>
                </Can>
              )}
            </div>
          </li>
        ))}
      </ul>
      {changes && (
        <section className="rounded-lg border p-3" aria-live="polite">
          <h3 className="mb-2 text-sm font-semibold">
            {t('ticketMapping.history.diffTitle', 'Changes from v{a} to v{b}', {
              a: Math.min(from ?? 0, to ?? 0),
              b: Math.max(from ?? 0, to ?? 0),
            })}
          </h3>
          {changes.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('ticketMapping.history.noChanges', 'No changes.')}
            </p>
          ) : (
            <ul className="grid gap-2 text-xs">
              {changes.map((c, i) => (
                <li key={i} className="rounded border p-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge
                      variant={
                        c.kind === 'removed'
                          ? 'destructive'
                          : c.kind === 'added'
                            ? 'default'
                            : 'secondary'
                      }
                    >
                      {t(`ticketMapping.changeKind.${c.kind}`, c.kind)}
                    </Badge>
                    <span className="text-muted-foreground">
                      {t(`ticketMapping.changeArea.${c.area}`, c.area)}
                    </span>
                    <span className="font-mono">{c.key}</span>
                  </div>
                  {c.kind !== 'added' && (
                    <p className="mt-1 break-all text-destructive">− {short(c.from)}</p>
                  )}
                  {c.kind !== 'removed' && (
                    <p className="mt-1 break-all text-emerald-700 dark:text-emerald-400">
                      + {short(c.to)}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  )
}
