'use client'

/**
 * Shown in the asset edit dialog when the chosen exposure or criticality is
 * lower than the asset's: what the change would do to the asset's open
 * findings (the API's preview), whether it needs a second person's approval,
 * and the reason the API requires when it would drop an open P0/P1 finding.
 * Raising risk shows nothing.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, ShieldAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  loweredRiskFields,
  previewRiskImpact,
  type RiskPreview,
} from '@/features/assets/lib/risk-impact'
import type { Asset } from '../types'

const DEBOUNCE_MS = 300

export interface RiskNoticeState {
  /** The change drops an open P0/P1 finding: a reason is required. */
  needsReason: boolean
  /** The change needs approval and nobody can approve it. */
  blocked: boolean
}

interface Props {
  asset: Asset
  criticality: string
  exposure: string
  reason: string
  onReasonChange: (reason: string) => void
  onStateChange: (state: RiskNoticeState) => void
}

export function AssetRiskImpactNotice({
  asset,
  criticality,
  exposure,
  reason,
  onReasonChange,
  onStateChange,
}: Props) {
  const { t } = useTranslation()
  // t may change identity between renders; the preview must not restart for it.
  const tRef = useRef(t)
  useEffect(() => {
    tRef.current = t
  }, [t])
  const lowered = useMemo(
    () => loweredRiskFields(asset, { criticality, exposure }),
    [asset, criticality, exposure]
  )
  const [preview, setPreview] = useState<RiskPreview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const active = lowered.length > 0

  useEffect(() => {
    if (!active) {
      setPreview(null)
      setError(null)
      return
    }
    let stale = false
    setPreview(null)
    setError(null)
    const timer = setTimeout(() => {
      previewRiskImpact(asset.id, {
        ...(lowered.includes('criticality') ? { criticality } : {}),
        ...(lowered.includes('exposure') ? { exposure } : {}),
      })
        .then((p) => !stale && setPreview(p))
        .catch(
          (e: unknown) =>
            !stale &&
            setError(
              getErrorMessage(
                e,
                tRef.current(
                  'assets.riskImpact.previewFailed',
                  'The impact of this change could not be read'
                )
              )
            )
        )
    }, DEBOUNCE_MS)
    return () => {
      stale = true
      clearTimeout(timer)
    }
  }, [active, asset.id, lowered, criticality, exposure])

  const drops = preview?.impact.p0_p1_drops ?? 0
  const approval = preview?.approval
  const state: RiskNoticeState = {
    needsReason: active && drops > 0,
    blocked: active && drops > 0 && !!approval && approval.required && !approval.satisfiable,
  }
  useEffect(() => {
    onStateChange(state)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.needsReason, state.blocked])

  if (!active) return null
  if (error) {
    return (
      <Alert variant="destructive" data-testid="risk-impact-error">
        <AlertTriangle />
        <AlertTitle>{t('assets.riskImpact.title', 'Lowering risk')}</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    )
  }
  if (!preview) {
    return (
      <p className="text-xs text-muted-foreground" data-testid="risk-impact-loading">
        {t('assets.riskImpact.loading', 'Checking what this change does to the open findings...')}
      </p>
    )
  }

  return (
    <div className="space-y-3" data-testid="risk-impact">
      <Alert variant={drops > 0 ? 'destructive' : 'default'}>
        {drops > 0 ? <ShieldAlert /> : <AlertTriangle />}
        <AlertTitle>{t('assets.riskImpact.title', 'Lowering risk')}</AlertTitle>
        <AlertDescription>
          <p>
            {preview.impact.class_drops === 0
              ? t(
                  'assets.riskImpact.noDrops',
                  'No open finding on this asset would move to a lower priority class.'
                )
              : t(
                  'assets.riskImpact.drops',
                  '{count} of {total} open findings on this asset would move to a lower priority class, {p0p1} of them from P0 or P1.',
                  {
                    count: preview.impact.class_drops,
                    total: preview.impact.open_findings,
                    p0p1: drops,
                  }
                )}
          </p>
          {preview.impact.moves.length > 0 && (
            <ul className="mt-1 list-disc pl-5" data-testid="risk-impact-moves">
              {preview.impact.moves.map((m) => (
                <li key={`${m.from}-${m.to}`}>
                  {t('assets.riskImpact.move', '{from} to {to}: {count}', {
                    from: m.from,
                    to: m.to,
                    count: m.count,
                  })}
                </li>
              ))}
            </ul>
          )}
          {drops > 0 && approval?.required && approval.satisfiable && (
            <p className="mt-2 font-medium" data-testid="risk-impact-needs-approval">
              {t(
                'assets.riskImpact.needsApproval',
                'The lowered values are not applied until a second person approves them; the rest of your changes are saved now.'
              )}
            </p>
          )}
          {drops > 0 && approval?.required && !approval.satisfiable && (
            <p className="mt-2 font-medium" data-testid="risk-impact-no-approver">
              {t(
                'assets.riskImpact.noApprover',
                'This change needs approval and the organization has no eligible approver. Ask an administrator to change the approval policy.'
              )}
            </p>
          )}
          {drops > 0 && approval && !approval.required && (
            <p className="mt-2" data-testid="risk-impact-alone">
              {t(
                'assets.riskImpact.alone',
                'The approval policy lets you decide this yourself. It is recorded in the audit log with your reason.'
              )}
            </p>
          )}
          {preview.pending_request && (
            <p className="mt-2 font-medium" data-testid="risk-impact-pending">
              {t(
                'assets.riskImpact.pending',
                'Another change to this asset is already waiting for approval; wait for it to be decided.'
              )}
            </p>
          )}
        </AlertDescription>
      </Alert>
      {drops > 0 && (
        <div>
          <Label htmlFor="riskChangeReason" className="text-sm font-medium">
            {t('assets.riskImpact.reason', 'Reason for lowering the risk')}
          </Label>
          <Textarea
            id="riskChangeReason"
            className="mt-1.5"
            rows={2}
            maxLength={1000}
            value={reason}
            onChange={(e) => onReasonChange(e.target.value)}
            placeholder={t(
              'assets.riskImpact.reasonPlaceholder',
              'Why is this asset less exposed or less critical than recorded?'
            )}
          />
        </div>
      )}
    </div>
  )
}
