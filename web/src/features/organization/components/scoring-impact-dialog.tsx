'use client'

/**
 * Review the impact of a risk scoring settings change before applying it
 * (API docs: architecture/scoring-versions.md, "Preview before apply").
 *
 * The numbers come from a dry run over every asset of the organization (and,
 * when the ownership floor changes, every open finding) with the same engine
 * the background workers use after the change, so what the dialog shows is
 * what applying does. Applying asks for re-authentication (step-up), runs
 * from now on for open findings, and never rewrites closed findings or
 * history.
 */

import { ArrowRight, Loader2 } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import type { RiskScoringPreviewResponse } from '../types/settings.types'

interface ScoringImpactDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  preview: RiskScoringPreviewResponse | null
  loading: boolean
  error: string | null
  applying: boolean
  onApply: () => void
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border px-3 py-2">
      <div className="text-lg font-semibold tabular-nums">{value.toLocaleString()}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  )
}

export function ScoringImpactDialog({
  open,
  onOpenChange,
  preview,
  loading,
  error,
  applying,
  onApply,
}: ScoringImpactDialogProps) {
  const { t } = useTranslation()
  const level = (v: string) => t(`riskScore.level.${v}`, v)
  const assets = preview?.assets
  const findings = preview?.affects_priority ? preview.findings : undefined

  return (
    <Dialog open={open} onOpenChange={(o) => !applying && onOpenChange(o)}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('riskScore.impact.title', 'Review the impact')}</DialogTitle>
          <DialogDescription>
            {t(
              'riskScore.impact.description',
              'What these settings change across the whole organization, computed exactly as the change will be applied.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          {loading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              {t('riskScore.impact.loading', 'Computing the impact…')}
            </div>
          )}
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {assets && (
            <section className="space-y-3">
              <h3 className="text-sm font-semibold">
                {t('riskScore.impact.assetsHeading', 'Asset risk scores')}
              </h3>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <Stat
                  label={t('riskScore.impact.assetsTotal', 'Assets')}
                  value={assets.total_assets}
                />
                <Stat
                  label={t('riskScore.impact.assetsChanged', 'Score changes')}
                  value={assets.changed}
                />
                <Stat label={t('riskScore.impact.assetsRaised', 'Go up')} value={assets.raised} />
                <Stat
                  label={t('riskScore.impact.assetsLowered', 'Go down')}
                  value={assets.lowered}
                />
              </div>
              {assets.band_changes.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('riskScore.impact.noBandChange', 'No asset changes risk band.')}
                </p>
              ) : (
                <ul
                  className="space-y-1 text-sm"
                  aria-label={t('riskScore.impact.bandChanges', 'Band changes')}
                >
                  {assets.band_changes.map((b) => (
                    <li key={`${b.from}-${b.to}`} className="flex items-center gap-2">
                      <span>{level(b.from)}</span>
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                      <span className="font-medium">{level(b.to)}</span>
                      <span className="ml-auto tabular-nums text-muted-foreground">
                        {t('riskScore.impact.assetCount', '{count} assets', { count: b.count })}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {assets.top_changes.length > 0 && (
                <div className="space-y-1">
                  <h4 className="text-xs font-medium text-muted-foreground">
                    {t('riskScore.impact.largestChanges', 'Largest changes')}
                  </h4>
                  <ul className="divide-y rounded-md border text-sm">
                    {assets.top_changes.map((a) => (
                      <li key={a.asset_id} className="flex items-center gap-2 px-3 py-1.5">
                        <span className="min-w-0 flex-1 truncate" title={a.asset_name}>
                          {a.asset_name}
                        </span>
                        <span className="tabular-nums text-muted-foreground">
                          {a.current_score}
                        </span>
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                        <span className="tabular-nums font-medium">{a.new_score}</span>
                        <span className="hidden w-24 text-right text-xs text-muted-foreground sm:inline">
                          {level(a.new_level)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}
          {findings && (
            <section className="space-y-3">
              <h3 className="text-sm font-semibold">
                {t('riskScore.impact.findingsHeading', 'Open finding priorities')}
              </h3>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <Stat
                  label={t('riskScore.impact.findingsOpen', 'Open findings')}
                  value={findings.open_findings}
                />
                <Stat
                  label={t('riskScore.impact.findingsChanged', 'Priority changes')}
                  value={findings.changed}
                />
                <Stat
                  label={t('riskScore.impact.deadlinesTightened', 'Deadlines move earlier')}
                  value={findings.deadlines_tightened}
                />
                <Stat
                  label={t('riskScore.impact.ticketsAffected', 'With a linked ticket')}
                  value={findings.tickets_affected}
                />
              </div>
              {findings.class_changes.length > 0 && (
                <ul
                  className="space-y-1 text-sm"
                  aria-label={t('riskScore.impact.classChanges', 'Priority changes')}
                >
                  {findings.class_changes.map((c) => (
                    <li key={`${c.from}-${c.to}`} className="flex items-center gap-2">
                      <span>{c.from || t('riskScore.impact.unclassified', 'Unclassified')}</span>
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                      <span className="font-medium">{c.to}</span>
                      <span className="ml-auto tabular-nums text-muted-foreground">
                        {t('riskScore.impact.findingCount', '{count} findings', { count: c.count })}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {findings.manual_overrides_kept > 0 && (
                <p className="text-xs text-muted-foreground">
                  {t(
                    'riskScore.impact.overridesKept',
                    '{count} findings with a manual priority keep it.',
                    {
                      count: findings.manual_overrides_kept,
                    }
                  )}
                </p>
              )}
            </section>
          )}
          {preview && (
            <p className="text-xs text-muted-foreground">
              {t(
                'riskScore.impact.forwardOnly',
                'Applies from now on: open findings and their assets are recomputed in the background. Closed findings, past trends and reports keep their values. A deadline only ever moves earlier. You will be asked to confirm your identity.'
              )}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={applying}>
            {t('riskScore.impact.cancel', 'Cancel')}
          </Button>
          <Button onClick={onApply} disabled={!preview || loading || applying}>
            {applying && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
            {t('riskScore.impact.apply', 'Apply changes')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
