'use client'

/**
 * Settings › Policies › Scan windows: the organization's policies (kind,
 * targets, schedule in its time zone, tier, whether it is open or blocking
 * now) and its overrides. Writes need scans:windows:manage; the API is the
 * authority, the panel only disables what the caller cannot do.
 */

import { useState } from 'react'
import { CalendarClock, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, GatedButton, TonePill } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

import {
  deleteScanWindowPolicy,
  invalidateScanWindows,
  useScanWindowPolicies,
} from '../api/use-scan-windows'
import { useSelectorOptions } from '../api/use-selector-options'
import { describeSchedule, policyState, tierLabel } from '../lib/schedule'
import { selectorSummary } from '../lib/selector'
import type { ScanWindowPolicy } from '../types'
import { OverridesSection } from './overrides-section'
import { PolicyDialog } from './policy-dialog'

const STATE_TONE = { open: 'success', blocked: 'destructive', idle: 'muted' } as const

export function ScanWindowsPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canManage = can(Permission.ScanWindowsManage)
  const { data, error, isLoading, mutate } = useScanWindowPolicies()
  const sources = useSelectorOptions()
  const [editing, setEditing] = useState<ScanWindowPolicy | 'new' | null>(null)
  const [deleting, setDeleting] = useState<ScanWindowPolicy | null>(null)
  const policies = data?.data ?? []
  const noWrite = t(
    'scanWindows.noManage',
    'You need the "Manage scan windows" permission to change policies'
  )

  return (
    <div className="space-y-8" data-testid="scan-windows-panel">
      <section aria-labelledby="policies-heading" className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <h2 id="policies-heading" className="text-base font-semibold">
            {t('scanWindows.policies', 'Policies')}
          </h2>
          <GatedButton
            allowed={canManage}
            reason={noWrite}
            size="sm"
            onClick={() => setEditing('new')}
          >
            <Plus className="size-4" aria-hidden />
            {t('scanWindows.add', 'Add policy')}
          </GatedButton>
        </div>
        {error ? (
          <ErrorState
            title={t('scanWindows.policies', 'Policies')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : policies.length === 0 ? (
          <EmptyState
            icon={CalendarClock}
            title={t('scanWindows.empty.title', 'No scan window policies')}
            description={t(
              'scanWindows.empty.description',
              'Scans run at any time. Add an allow policy for testing windows (for example business hours only), or a blackout for maintenance and change freezes.'
            )}
          />
        ) : (
          <div className="space-y-3">
            {policies.map((p) => {
              const state = policyState(p, t)
              return (
                <Card key={p.id} data-testid="policy-row">
                  <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
                    <div className="min-w-0 space-y-1.5">
                      <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                        <span className="break-words">{p.name}</span>
                        <Badge
                          variant={p.kind === 'blackout' ? 'destructive' : 'secondary'}
                          className="font-normal"
                        >
                          {p.kind === 'blackout'
                            ? t('scanWindows.kind.blackout', 'Blackout')
                            : t('scanWindows.kind.allow', 'Allow')}
                        </Badge>
                        <TonePill
                          tone={STATE_TONE[state.tone]}
                          label={state.label}
                          state={state.tone}
                        />
                      </CardTitle>
                      <CardDescription className="space-y-0.5">
                        <span className="block break-words" data-testid="policy-targets">
                          {selectorSummary(p.selector, sources.names, t)}
                        </span>
                        <span className="block break-words">
                          {describeSchedule(p, t).join('; ')} ({p.timezone})
                        </span>
                        <span className="block">{tierLabel(p.min_tier, t)}</span>
                      </CardDescription>
                      {p.description && (
                        <p className="break-words text-sm text-muted-foreground">{p.description}</p>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <GatedButton
                        allowed={canManage}
                        reason={noWrite}
                        variant="outline"
                        size="sm"
                        onClick={() => setEditing(p)}
                      >
                        {t('scanWindows.edit', 'Edit')}
                      </GatedButton>
                      <GatedButton
                        allowed={canManage}
                        reason={noWrite}
                        variant="ghost"
                        size="sm"
                        aria-label={t('scanWindows.deleteNamed', 'Delete {name}', {
                          name: p.name ?? '',
                        })}
                        onClick={() => setDeleting(p)}
                      >
                        <Trash2 className="size-4" aria-hidden />
                      </GatedButton>
                    </div>
                  </CardHeader>
                </Card>
              )
            })}
          </div>
        )}
      </section>

      <OverridesSection policies={policies} />

      {canManage && (
        <PolicyDialog
          open={!!editing}
          onOpenChange={(o) => !o && setEditing(null)}
          policy={editing === 'new' ? null : editing}
          sources={sources}
        />
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('scanWindows.deleteTitle', 'Delete scan window policy')}
        desc={t(
          'scanWindows.deleteDesc',
          'Delete "{name}"? Work it holds now is released at once.',
          {
            name: deleting?.name ?? '',
          }
        )}
        confirmText={t('scanWindows.delete', 'Delete')}
        destructive
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target?.id) return
          deleteScanWindowPolicy(target.id)
            .then(async () => {
              toast.success(t('scanWindows.toast.deleted', 'Policy deleted'))
              await invalidateScanWindows()
            })
            .catch((e: unknown) =>
              toast.error(
                getErrorMessage(
                  e,
                  t('scanWindows.toast.deleteFailed', 'Could not delete the policy')
                )
              )
            )
        }}
      />
    </div>
  )
}
