'use client'

/** Break-glass: let one commit pass the gate for a limited time, audited (api RFC-051). */

import { useEffect, useState } from 'react'
import { useUrlFilter } from '@/hooks/use-url-param'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { ErrorState, GatedButton, SettingsSection } from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { formatLocalized } from '@/lib/format-date'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useAssetNameMap } from '@/features/threat-model/hooks/use-threat-model-refs'
import { useGateOverrides, useRevokeGateOverride } from '../api/use-ci'
import { shortSHA } from '../lib/ci'
import { CIOverrideDialog } from './ci-override-dialog'

// ───────────────────────────────────────────────────── break-glass ───

/** The heading id of the break-glass section, the target of `?section=break-glass` links. */
export const BREAK_GLASS_ID = 'ci-setup-break-glass'

/**
 * Break-glass on the Runs tab, next to the failed run it unblocks:
 * "Override a commit", and the overrides on request (the Runs tab reads only
 * its runs on load; an old `?section=break-glass` link opens them): active
 * ones first, past ones folded. Repositories show by name (the caller's data
 * scope decides which names resolve).
 */
export function CIOverrides({ canOverride }: { canOverride: boolean }) {
  const [sectionParam] = useUrlFilter('section', '')
  const [listed, setListed] = useState(sectionParam === 'break-glass')
  const { data, error, isLoading, mutate } = useGateOverrides({ enabled: listed })
  const { trigger: revoke } = useRevokeGateOverride()
  const [open, setOpen] = useState(false)
  const [pendingRevoke, setPendingRevoke] = useState<{ id: string; sha: string } | null>(null)
  const { t, locale } = useTranslation()
  const overrides = data?.data ?? []
  const active = overrides.filter((o) => o.active)
  const past = overrides.filter((o) => !o.active)
  const [showPast, setShowPast] = useState(false)
  const shown = showPast ? overrides : active
  const { nameFor } = useAssetNameMap(overrides.map((o) => o.repository_asset_id ?? ''))
  // An old `?section=break-glass` link lands here: scroll once the list is in.
  useEffect(() => {
    if (sectionParam !== 'break-glass' || isLoading) return
    document.getElementById(BREAK_GLASS_ID)?.scrollIntoView?.({ block: 'start' })
  }, [sectionParam, isLoading])

  return (
    <SettingsSection
      id={BREAK_GLASS_ID}
      title={t('scans.ci.breakGlass.tab', 'Break-glass')}
      description={t(
        'scans.ci.breakGlass.description',
        'Let one commit of one repository pass the gate for a limited time. Every override and every run it lets through is recorded in the audit log.'
      )}
      actions={
        <GatedButton
          allowed={canOverride}
          reason={t(
            'scans.ci.breakGlass.ownersOnly',
            'Only owners and administrators can override the gate'
          )}
          size="sm"
          variant="outline"
          onClick={() => setOpen(true)}
        >
          <Plus className="size-4" aria-hidden />{' '}
          {t('scans.ci.breakGlass.add', 'Override a commit')}
        </GatedButton>
      }
    >
      {!listed ? (
        <Button
          variant="ghost"
          size="sm"
          className="self-start"
          onClick={() => setListed(true)}
          data-testid="ci-overrides-show"
        >
          {t('scans.ci.breakGlass.showList', 'Show overrides')}
        </Button>
      ) : error ? (
        <ErrorState
          title={t('scans.ci.breakGlass.list', 'break-glass overrides')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : (
        <>
          {active.length === 0 && (
            <p className="text-sm text-muted-foreground" data-testid="ci-overrides-none-active">
              {t('scans.ci.breakGlass.noneActive', 'No commit passes the gate by override now.')}
            </p>
          )}
          {shown.length > 0 && (
            <ul className="divide-y rounded-lg border" data-testid="ci-overrides">
              {shown.map((o) => (
                <li
                  key={o.id}
                  className="flex flex-wrap items-center justify-between gap-2 p-3 text-sm"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono">{shortSHA(o.commit_sha)}</span>
                      {o.active ? (
                        <Badge variant="destructive">
                          {t('scans.ci.breakGlass.active', 'Active')}
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          {o.revoked_at
                            ? t('scans.ci.breakGlass.revoked', 'Revoked')
                            : t('scans.ci.breakGlass.expired', 'Expired')}
                        </Badge>
                      )}
                      <span className="text-muted-foreground">
                        {t('scans.ci.breakGlass.by', 'by {name}', {
                          name:
                            o.created_by || t('scans.ci.breakGlass.anAdmin', 'an administrator'),
                        })}
                      </span>
                    </div>
                    <p className="break-words">{o.reason}</p>
                    <p className="text-xs text-muted-foreground">
                      {t('scans.ci.breakGlass.untilRepo', '{repository}, until {time}', {
                        time: o.expires_at
                          ? formatLocalized(o.expires_at, locale, { time: true })
                          : '',
                        repository: nameFor(o.repository_asset_id),
                      })}
                    </p>
                  </div>
                  {o.active && (
                    <GatedButton
                      allowed={canOverride}
                      reason={t(
                        'scans.ci.breakGlass.noRevokePermission',
                        'Only owners and administrators can revoke an override'
                      )}
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        setPendingRevoke({ id: o.id ?? '', sha: shortSHA(o.commit_sha) })
                      }
                    >
                      {t('confirm.revoke', 'Revoke')}
                    </GatedButton>
                  )}
                </li>
              ))}
            </ul>
          )}
          {past.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="self-start"
              onClick={() => setShowPast((v) => !v)}
            >
              {showPast
                ? t('scans.ci.breakGlass.hidePast', 'Hide past overrides')
                : t('scans.ci.breakGlass.showPast', 'Show {count} past overrides', {
                    count: past.length,
                  })}
            </Button>
          )}
        </>
      )}
      <CIOverrideDialog open={open} onOpenChange={setOpen} onCreated={() => void mutate()} />
      <ConfirmDialog
        open={pendingRevoke !== null}
        onOpenChange={(o) => !o && setPendingRevoke(null)}
        destructive
        title={t('confirm.gateOverride.revokeTitle', 'Revoke the override for commit {sha}?', {
          sha: pendingRevoke?.sha ?? '',
        })}
        desc={t(
          'confirm.gateOverride.revokeDesc',
          'The commit is checked against the gate again from its next pipeline run, and fails it if its findings still do. A revoked override cannot be restored; create a new one if needed.'
        )}
        confirmText={t('confirm.revoke', 'Revoke')}
        handleConfirm={async () => {
          if (!pendingRevoke) return
          try {
            await revoke(pendingRevoke.id)
            toast.success(t('scans.ci.breakGlass.revokedToast', 'Override revoked'))
            setPendingRevoke(null)
            void mutate()
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      />
    </SettingsSection>
  )
}
