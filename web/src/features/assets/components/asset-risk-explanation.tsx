/**
 * "Why this score": the factors of an asset's risk score and the open
 * findings that drive it (GET /api/v1/assets/{id}/risk,
 * api/docs/architecture/asset-risk-score.md).
 */

'use client'

import Link from '@/components/link'
import { Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/features/shared'
import type { Severity } from '@/features/shared/types'
import { useTranslation } from '@/context/i18n-provider'
import { useAssetRisk } from '../hooks/use-asset-risk'
import { SEVERITY_TEXT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'

const LIKELIHOOD_IMPACT = 'likelihood_impact'

interface AssetRiskExplanationProps {
  assetId: string
}

export function AssetRiskExplanation({ assetId }: AssetRiskExplanationProps) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useAssetRisk(assetId)

  if (isLoading) {
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
        {t('riskScore.why.loading', 'Loading the explanation…')}
      </p>
    )
  }
  if (error || !data) {
    return (
      <p className="text-sm text-muted-foreground">
        {t('riskScore.why.loadError', 'Could not load the explanation.')}
      </p>
    )
  }

  const b = data.breakdown
  const criticalityLabel = (c: string) => t(`criticality.${c || 'none'}`, c || 'none')
  const exposureLabel = (e: string) => t(`assets.form.exposure.${e || 'unknown'}`, e || 'unknown')
  const openTiers = b.tiers.filter((tier) => tier.count > 0 || tier.effective > 0)

  return (
    <div className="space-y-4 text-sm" data-testid="asset-risk-explanation">
      {data.pending && (
        <p className="text-xs text-muted-foreground">
          {t(
            'riskScore.why.pending',
            'A rescore is queued; these figures already use the current inputs.'
          )}
        </p>
      )}

      {b.model === LIKELIHOOD_IMPACT ? (
        <p className="font-medium tabular-nums">
          {b.control_reduction > 0
            ? t(
                'riskScore.why.formulaControls',
                'Findings {findings} × exposure {exposure}% × criticality {criticality}% × (1 − {reduction}% controls)',
                {
                  findings: b.findings_score,
                  exposure: b.exposure_factor,
                  criticality: b.criticality_factor,
                  reduction: b.control_reduction,
                }
              )
            : t(
                'riskScore.why.formula',
                'Findings {findings} × exposure {exposure}% × criticality {criticality}%',
                {
                  findings: b.findings_score,
                  exposure: b.exposure_factor,
                  criticality: b.criticality_factor,
                }
              )}{' '}
          = {b.score}
        </p>
      ) : (
        <p className="font-medium tabular-nums">
          {t(
            'riskScore.why.weighted',
            'Weighted model: findings {findings}, exposure {exposure}, criticality {criticality}',
            {
              findings: b.findings_score,
              exposure: b.exposure_factor,
              criticality: b.criticality_factor,
            }
          )}
        </p>
      )}

      <ul className="space-y-1 text-muted-foreground">
        <li>
          {t('riskScore.why.exposure', 'Exposure: {value} ({factor}%)', {
            value: exposureLabel(b.exposure),
            factor: b.exposure_factor,
          })}
        </li>
        <li>
          {t('riskScore.why.criticality', 'Criticality: {value} ({factor}%)', {
            value: criticalityLabel(b.effective_criticality),
            factor: b.criticality_factor,
          })}
          {b.effective_criticality !== b.criticality && (
            <>
              {' '}
              {t('riskScore.why.raisedFrom', 'raised from {value} by its business context', {
                value: criticalityLabel(b.criticality),
              })}
            </>
          )}
        </li>
        {b.crown_jewel && (
          <li>{t('riskScore.why.crownJewel', 'Crown jewel: counts as critical')}</li>
        )}
      </ul>

      {openTiers.length === 0 ? (
        <p className="text-muted-foreground">
          {t('riskScore.why.noFindings', 'No open findings: nothing adds risk to this asset.')}
        </p>
      ) : (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">
            {t('riskScore.why.tiers', 'Findings by severity')}
          </p>
          <ul className="space-y-1">
            {openTiers.map((tier) => (
              <li key={tier.severity} className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={tier.severity as Severity} />
                <span className="tabular-nums">
                  {t('riskScore.why.tierRow', '{count} open', { count: tier.count })}
                </span>
                {tier.exploitable > 0 && (
                  <span className={cn('text-xs tabular-nums', SEVERITY_TEXT_COLORS.critical)}>
                    {t('riskScore.why.exploitable', '{count} exploitable', {
                      count: tier.exploitable,
                    })}
                  </span>
                )}
                <span className="text-xs text-muted-foreground tabular-nums">
                  {t('riskScore.why.tierScore', 'tier {score}', { score: tier.score })}
                </span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            {t(
              'riskScore.why.howItWorks',
              'The worst severity sets the findings score; more findings of the same severity add less each time. Known-exploited findings count one severity higher.'
            )}
          </p>
        </div>
      )}

      {data.contributors.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">
            {t('riskScore.why.topFindings', 'Findings that drive it')}
          </p>
          <ul className="space-y-1.5">
            {data.contributors.map((c) => (
              <li key={c.finding_id} className="flex min-w-0 flex-wrap items-center gap-2">
                <SeverityBadge severity={c.severity as Severity} />
                <Link
                  href={`/findings/${c.finding_id}`}
                  className="min-w-0 flex-1 truncate text-primary hover:underline"
                  title={c.title}
                >
                  {c.title}
                </Link>
                {c.in_kev && <Badge variant="destructive">{t('riskScore.why.kev', 'KEV')}</Badge>}
                {c.exploit_available && (
                  <Badge variant="outline">{t('riskScore.why.exploit', 'Exploit')}</Badge>
                )}
                {c.epss_score !== undefined && c.epss_score > 0 && (
                  <Badge variant="outline" className="tabular-nums">
                    {t('riskScore.why.epss', 'EPSS {value}%', {
                      value: Math.round(c.epss_score * 1000) / 10,
                    })}
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
