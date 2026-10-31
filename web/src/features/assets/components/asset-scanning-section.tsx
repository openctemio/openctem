'use client'

/**
 * "Scope and scanning" on the asset overview (research 129 §3.1): may scans
 * reach this asset, why, and the one or two actions that change it, without
 * opening the Details tab. The answer is the API's (`GET
 * /assets/{id}/attribution`, the scan gate's own result); every action calls
 * an existing endpoint with its existing gate and is hidden without the
 * permission:
 *
 * - Add to scope: a scope entry for the exact name (`scope:write`);
 * - Mark out of scope: an exclusion or "not ours" (`scope:write` /
 *   `assets:write`), the inventory's own dialog;
 * - Confirm and allow scanning: a wildcard-only name is held until a person
 *   confirms it is theirs (`assets:write`);
 * - Scan now: a quick scan of the asset (`scans:write` + `scans:execute`),
 *   only when the gate allows it and the type has a scan target;
 * - Scan with Tenable.sc: an IP address or host scanned now through a
 *   Tenable.sc connector (`scans:write`, when the organization has one).
 */

import { useState } from 'react'
import { Loader2, Play, Radar, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DetailSection, ErrorState } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import {
  ScopeEntryDialog,
  type ScopeEntryDraft,
} from '@/features/scope/components/scope-entry-dialog'
import { LazyScanAssetsDialog } from '@/features/scans/components/lazy-dialogs'
import { TenableScanNowButton } from '@/features/integrations/components/scanners/tenable-scan-now'
import { isTenableScannableAssetType } from '@/features/integrations/lib/tenable-sc'
import { useAssetAttribution, useDecideAttribution } from '../hooks/use-asset-attribution'
import {
  ATTRIBUTION_STATE_CLASS,
  attributionStateLabel,
  scanStanding,
  scopeStandingText,
  type AssetAttribution,
} from '../lib/attribution'
import type { Asset } from '../types/asset.types'
import { MarkOutOfScopeAction } from './inventory/mark-out-of-scope-action'

/** Types a quick scan can target by the asset's name (a host name or an address). */
const QUICK_SCAN_TYPES = new Set(['domain', 'subdomain', 'ip_address'])

/** Whether "Mark out of scope" still means something for this answer. */
function canMarkOut(a: AssetAttribution): boolean {
  return a.state !== 'rejected' && a.blocked_code !== 'excluded'
}

export interface AssetScanningSectionProps {
  asset: Pick<Asset, 'id' | 'name' | 'type' | 'subType'> & Partial<Asset>
  /** Opens the full ownership panel (the Details tab). */
  onShowDetails?: () => void
}

export function AssetScanningSection({ asset, onShowDetails }: AssetScanningSectionProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { attribution, error, isLoading, mutate } = useAssetAttribution(asset.id)
  const { decide, saving } = useDecideAttribution(asset.id)
  const [draft, setDraft] = useState<ScopeEntryDraft | null>(null)
  const [scanOpen, setScanOpen] = useState(false)

  if (isLoading) {
    return (
      <DetailSection title={t('assets.scanning.title', 'Scope and scanning')} icon={Radar}>
        <Skeleton className="h-5 w-2/3" />
      </DetailSection>
    )
  }
  // A failed request says so, with a retry: the answer to "may scans reach
  // it" must not vanish silently.
  if (error && !attribution) {
    return (
      <DetailSection title={t('assets.scanning.title', 'Scope and scanning')} icon={Radar}>
        <ErrorState
          title={t('assetDetail.scanningErrorTitle', 'scope and scanning')}
          error={error}
          onRetry={() => mutate()}
        />
      </DetailSection>
    )
  }
  // No answer without assets:read: say nothing rather than guess.
  if (!attribution) return null

  const scope = scopeStandingText(t, attribution)
  const allowed = attribution.active_checks_allowed
  const wildcard = attribution.blocked_code === 'wildcard_only'
  const canAddScope = can(Permission.ScopeWrite) && !allowed && !!scope?.canAdd
  const canConfirm = can(Permission.AssetsWrite) && wildcard
  const canExclude =
    (can(Permission.ScopeWrite) || can(Permission.AssetsWrite)) && canMarkOut(attribution)
  const tenableType = isTenableScannableAssetType(asset.type) && can(Permission.ScansWrite)
  const canScan =
    allowed &&
    QUICK_SCAN_TYPES.has(asset.type) &&
    can(Permission.ScansWrite) &&
    can(Permission.ScansExecute)

  const confirm = async () => {
    try {
      const next = await decide('confirmed')
      await mutate(next, { revalidate: false })
      toast.success(t('assets.scanning.confirmed', 'Confirmed as yours; scans may reach it now'))
      await mutate()
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('assets.attribution.toast.failed', 'Could not save the decision')
      )
    }
  }

  return (
    <DetailSection
      title={t('assets.scanning.title', 'Scope and scanning')}
      icon={Radar}
      actions={
        onShowDetails ? (
          <Button variant="link" size="sm" className="h-auto p-0" onClick={onShowDetails}>
            {t('assets.scanning.details', 'Why')}
          </Button>
        ) : undefined
      }
    >
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Badge
            variant="outline"
            className={cn('border-transparent', ATTRIBUTION_STATE_CLASS[attribution.state])}
          >
            <ShieldCheck className="me-1 h-3 w-3" aria-hidden />
            {attributionStateLabel(t, attribution.state)}
          </Badge>
          <span className={cn(allowed ? 'text-foreground' : 'text-muted-foreground')}>
            {allowed
              ? (scope?.text ?? t('assets.scanning.allowed', 'Scans can reach this asset.'))
              : scanStanding(t, attribution)}
          </span>
        </div>
        {(canAddScope || canConfirm || canExclude || canScan || tenableType) && (
          <div className="flex flex-wrap items-center gap-2">
            {canScan && (
              <Button size="sm" className="h-8" onClick={() => setScanOpen(true)}>
                <Play className="me-1.5 h-3.5 w-3.5" aria-hidden />
                {t('assets.scanning.scanNow', 'Scan now')}
              </Button>
            )}
            {tenableType && (
              <TenableScanNowButton
                assetIds={[asset.id]}
                className="h-8"
                label={t('assets.scanning.tenableScan', 'Scan with Tenable.sc')}
                title={t(
                  'assets.scanning.tenableScanTitle',
                  "Scan this asset now through the organization's Tenable.sc connector"
                )}
              />
            )}
            {canAddScope && (
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                onClick={() =>
                  setDraft({
                    pattern: asset.name,
                    target_type: asset.type === 'ip_address' ? 'ip_address' : undefined,
                  })
                }
              >
                {t('assets.attribution.addToScope', 'Add to scope')}
              </Button>
            )}
            {canConfirm && (
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                disabled={saving}
                onClick={confirm}
              >
                {saving && <Loader2 className="me-1 h-3 w-3 animate-spin" />}
                {t('assets.scanning.allowWildcard', 'Confirm and allow scanning')}
              </Button>
            )}
            {canExclude && (
              <MarkOutOfScopeAction selected={[asset as Asset]} onDone={() => void mutate()} />
            )}
          </div>
        )}
      </div>
      <ScopeEntryDialog
        open={draft !== null}
        draft={draft ?? undefined}
        onOpenChange={(o) => !o && setDraft(null)}
        onCreated={() => void mutate()}
      />
      {canScan && (
        <LazyScanAssetsDialog
          open={scanOpen}
          onOpenChange={setScanOpen}
          candidates={[{ id: asset.id, label: asset.name, target: asset.name.trim() }]}
        />
      )}
    </DetailSection>
  )
}
