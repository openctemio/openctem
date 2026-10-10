'use client'

/**
 * Active and recent overrides, the "Override windows" action
 * (scans:windows:override) and "End now" on an active one.
 */

import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, GatedButton } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

import {
  invalidateScanWindows,
  revokeScanWindowOverride,
  useScanWindowOverrides,
} from '../api/use-scan-windows'
import { formatInZone } from '../lib/schedule'
import type { ScanWindowOverride, ScanWindowPolicy } from '../types'
import { OverrideDialog } from './override-dialog'

/** Recent (ended) overrides listed under the active ones. */
const RECENT = 5

export function OverridesSection({ policies }: { policies: ScanWindowPolicy[] }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canOverride = can(Permission.ScanWindowsOverride)
  const { data, error, isLoading, mutate } = useScanWindowOverrides()
  const [open, setOpen] = useState(false)
  const [ending, setEnding] = useState<ScanWindowOverride | null>(null)
  const all = data?.data ?? []
  const active = all.filter((o) => o.active)
  const recent = all.filter((o) => !o.active).slice(0, RECENT)
  const noPermission = t(
    'scanWindows.override.noPermission',
    'Only owners and administrators can override scan windows'
  )

  const row = (o: ScanWindowOverride) => (
    <li
      key={o.id}
      className="flex flex-wrap items-start justify-between gap-2 px-3 py-2 text-sm"
      data-testid="override-row"
    >
      <div className="min-w-0 space-y-0.5">
        <p className="flex flex-wrap items-center gap-2">
          <span className="font-medium">
            {o.policy_name ||
              (o.policy_id
                ? t('scanWindows.override.onePolicy', 'One policy')
                : t('scanWindows.override.all', 'Every policy'))}
          </span>
          {o.active ? (
            <Badge variant="destructive" className="font-normal">
              {t('scanWindows.override.activeUntil', 'Active until {at}', {
                at: formatInZone(o.ends_at),
              })}
            </Badge>
          ) : (
            <Badge variant="secondary" className="font-normal">
              {o.revoked_at
                ? t('scanWindows.override.endedEarly', 'Ended early {at}', {
                    at: formatInZone(o.revoked_at),
                  })
                : t('scanWindows.override.ended', 'Ended {at}', { at: formatInZone(o.ends_at) })}
            </Badge>
          )}
        </p>
        <p className="break-words text-xs text-muted-foreground [unicode-bidi:isolate]" dir="auto">
          {o.reason}
        </p>
        <p className="text-xs text-muted-foreground">
          {t('scanWindows.override.started_at', 'Started {at}', { at: formatInZone(o.starts_at) })}
        </p>
      </div>
      {o.active && canOverride && (
        <Button variant="outline" size="sm" onClick={() => setEnding(o)}>
          {t('scanWindows.override.endNow', 'End now')}
        </Button>
      )}
    </li>
  )

  return (
    <section
      aria-labelledby="overrides-heading"
      className="space-y-3"
      data-testid="overrides-section"
    >
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 id="overrides-heading" className="text-base font-semibold">
            {t('scanWindows.override.heading', 'Overrides')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'scanWindows.override.headingHint',
              'Lift policy windows for a short time in an emergency. Bug-bounty program windows are never lifted.'
            )}
          </p>
        </div>
        <GatedButton
          allowed={canOverride}
          reason={noPermission}
          size="sm"
          variant="outline"
          onClick={() => setOpen(true)}
        >
          <ShieldAlert className="size-4" aria-hidden />
          {t('scanWindows.override.action', 'Override windows')}
        </GatedButton>
      </div>
      {error ? (
        <ErrorState
          title={t('scanWindows.override.heading', 'Overrides')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-12 w-full" />
      ) : active.length + recent.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('scanWindows.override.none', 'No overrides yet.')}
        </p>
      ) : (
        <ul className="divide-y rounded-md border">
          {active.map(row)}
          {recent.map(row)}
        </ul>
      )}

      <OverrideDialog open={open} onOpenChange={setOpen} policies={policies} />
      <ConfirmDialog
        open={!!ending}
        onOpenChange={(o) => !o && setEnding(null)}
        title={t('scanWindows.override.endTitle', 'End the override now?')}
        desc={t('scanWindows.override.endDesc', 'The windows apply again at once.')}
        confirmText={t('scanWindows.override.endNow', 'End now')}
        handleConfirm={() => {
          const target = ending
          setEnding(null)
          if (!target?.id) return
          revokeScanWindowOverride(target.id)
            .then(async () => {
              toast.success(t('scanWindows.override.endedToast', 'Override ended'))
              await invalidateScanWindows()
            })
            .catch((e: unknown) =>
              toast.error(
                getErrorMessage(
                  e,
                  t('scanWindows.override.endFailed', 'Could not end the override')
                )
              )
            )
        }}
      />
    </section>
  )
}
