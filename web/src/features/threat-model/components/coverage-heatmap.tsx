'use client'

import { StatusLozenge } from '@/components/ui/status-lozenge'
import { STATUS_TONE_CLASS } from '@/lib/status-colors'
import { useTranslation } from '@/context/i18n-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { EmptyState } from '@/features/shared'
import { cn } from '@/lib/utils'
import { Download, Grid3x3 } from 'lucide-react'
import { toast } from 'sonner'
import { useThreatModelCoverage } from '../hooks/use-threat-model-coverage'
import {
  getThreatStatusStyle,
  THREAT_STATUS_ORDER,
  THREAT_STATUS_STYLES,
} from '../lib/threat-status'
import { buildNavigatorLayer, navigatorFileName } from '../lib/navigator-layer'
import type { CoverageTechnique, ThreatModelCoverage } from '../types'

interface CoverageHeatmapProps {
  modelId: string
  modelName: string
}

/**
 * ATT&CK coverage matrix: one column per kill-chain tactic
 * (backend order), each a stack of technique cells colored by worst-case
 * status. Horizontal-scrolls so the page never scrolls sideways. Includes a
 * client-side Navigator layer (v4.5) export.
 */
export function CoverageHeatmap({ modelId, modelName }: CoverageHeatmapProps) {
  const { t } = useTranslation()
  const { coverage, isLoading } = useThreatModelCoverage(modelId)

  if (isLoading || !coverage) {
    return <Skeleton className="h-96 w-full" data-testid="coverage-loading" />
  }

  const hasTechniques = coverage.totals.techniques > 0

  return (
    <div className="space-y-4">
      <CoverageToolbar coverage={coverage} modelName={modelName} disabled={!hasTechniques} />
      {hasTechniques ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('threatModel.heatmap.title', 'ATT&CK coverage matrix')}
            </CardTitle>
            <CardDescription>
              {t(
                'threatModel.heatmap.description',
                'Columns are kill-chain tactics. Each cell is a technique colored by its worst-case threat status. {techniques, plural, one {# technique} other {# techniques}}, {pct}% coverage.',
                {
                  techniques: coverage.totals.techniques,
                  pct: Math.round(coverage.totals.coverage_pct),
                }
              )}
            </CardDescription>
            <StatusLegend />
          </CardHeader>
          <CardContent className="overflow-x-auto pb-6" data-testid="coverage-matrix">
            <div className="flex min-w-max gap-2">
              {coverage.tactics.map((tactic) => (
                <TacticColumn
                  key={tactic.tactic}
                  tactic={tactic.tactic}
                  techniques={tactic.techniques}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      ) : (
        <EmptyState
          icon={Grid3x3}
          title={t('threatModel.heatmap.emptyTitle', 'No techniques in scope')}
          description={t(
            'threatModel.heatmap.emptyDescription',
            'This threat model has no derived ATT&CK techniques yet. Refresh it once attack paths and attacker profiles are available.'
          )}
        />
      )}
    </div>
  )
}

function CoverageToolbar({
  coverage,
  modelName,
  disabled,
}: {
  coverage: ThreatModelCoverage
  modelName: string
  disabled: boolean
}) {
  const { t } = useTranslation()
  const handleDownload = () => {
    const { layer, unmappedTactics } = buildNavigatorLayer(coverage, modelName)
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = navigatorFileName(modelName)
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    if (unmappedTactics.length > 0) {
      toast.warning(
        t(
          'threatModel.heatmap.layerUnmapped',
          'Layer exported. Unmapped tactic shortnames: {names}',
          { names: unmappedTactics.join(', ') }
        )
      )
    } else {
      toast.success(t('threatModel.heatmap.layerDownloaded', 'ATT&CK Navigator layer downloaded.'))
    }
  }

  return (
    <div className="flex items-center justify-between gap-3">
      <p className="text-muted-foreground text-sm">
        {t('threatModel.heatmap.open', 'Open')}{' '}
        <span className="text-destructive font-medium">{coverage.totals.open}</span>,{' '}
        {t('threatModel.status.theoretical', 'Theoretical')}{' '}
        <span className="font-medium">{coverage.totals.theoretical}</span>,{' '}
        {t('threatModel.heatmap.coveredMitigated', 'Covered/Mitigated')}{' '}
        <span className="text-success font-medium">
          {coverage.totals.covered + coverage.totals.mitigated}
        </span>
      </p>
      <Button variant="outline" size="sm" onClick={handleDownload} disabled={disabled}>
        <Download className="me-2 h-4 w-4" />
        {t('threatModel.heatmap.download', 'Download Navigator layer')}
      </Button>
    </div>
  )
}

function StatusLegend() {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap gap-3 pt-2">
      {THREAT_STATUS_ORDER.map((status) => {
        const style = THREAT_STATUS_STYLES[status]
        return (
          <StatusLozenge
            key={status}
            tone={style.tone}
            icon={style.icon}
            label={t(style.labelKey, status)}
            value={status}
          />
        )
      })}
    </div>
  )
}

function TacticColumn({ tactic, techniques }: { tactic: string; techniques: CoverageTechnique[] }) {
  return (
    <div className="flex w-40 shrink-0 flex-col gap-1" data-testid="tactic-column">
      <div className="bg-muted/60 sticky top-0 rounded px-2 py-1.5 text-center">
        <p className="truncate text-xs font-semibold" title={tactic}>
          {tactic}
        </p>
        <p className="text-muted-foreground text-[10px]">{techniques.length}</p>
      </div>
      {techniques.map((tech) => (
        <TechniqueCell key={tech.technique_id} tech={tech} />
      ))}
    </div>
  )
}

function TechniqueCell({ tech }: { tech: CoverageTechnique }) {
  const { t } = useTranslation()
  const style = getThreatStatusStyle(tech.status)
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            data-testid={`technique-cell-${tech.technique_id}`}
            data-status={tech.status}
            className={cn(
              'cursor-default rounded-sm border px-2 py-1.5 text-start transition-colors',
              STATUS_TONE_CLASS[style.tone]
            )}
          >
            <p className="font-mono text-[10px] font-semibold leading-tight">{tech.technique_id}</p>
            <p className="truncate text-[11px] leading-tight" title={tech.technique_name}>
              {tech.technique_name}
            </p>
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <div className="space-y-1 text-sm">
            <p className="font-semibold">{tech.technique_name}</p>
            <p className="text-muted-foreground font-mono text-xs">
              {tech.technique_id}, {t(style.labelKey, tech.status)},{' '}
              {t('threatModel.heatmap.maxScore', 'max {score}', { score: tech.max_score })}
            </p>
            <div className="text-muted-foreground text-xs">
              {t(
                'threatModel.heatmap.techniqueCounts',
                '{n, plural, one {# threat} other {# threats}}: open {open}, mitigated {mitigated}, covered {covered}, accepted {accepted}, theoretical {theoretical}',
                {
                  n: tech.threat_count,
                  open: tech.counts.open,
                  mitigated: tech.counts.mitigated,
                  covered: tech.counts.covered,
                  accepted: tech.counts.accepted,
                  theoretical: tech.counts.theoretical,
                }
              )}
            </div>
            {tech.mitigation_ids.length > 0 && (
              <p className="text-muted-foreground text-xs">
                {t('threatModel.heatmap.mitigations', 'Mitigations: {ids}', {
                  ids: tech.mitigation_ids.join(', '),
                })}
              </p>
            )}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
