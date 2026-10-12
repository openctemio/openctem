/**
 * Asset Compatibility Warning Component
 *
 * Shows a warning when selected asset groups contain assets
 * incompatible with the selected scanner/tool
 */

import { AlertTriangle, CheckCircle, Info, XCircle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Button } from '@/components/ui/button'
import { ChevronDown } from 'lucide-react'
import { useState } from 'react'
import type { AssetCompatibilityPreview } from '../types/scan.types'
import { getCompatibilityStatus } from '../types/scan.types'
import { ASSET_TYPE_LABELS } from '@/features/assets/types/asset.types'

interface AssetCompatibilityWarningProps {
  preview: AssetCompatibilityPreview
  className?: string
  /** Whether to show detailed breakdown */
  showDetails?: boolean
}

export function AssetCompatibilityWarning({
  preview,
  className,
  showDetails = true,
}: AssetCompatibilityWarningProps) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  const toolName = preview.toolName || t('scans.compat.thisTool')
  const status = getCompatibilityStatus(preview.compatibilityPercent)
  // Don't show if fully compatible
  if (status === 'full') {
    return (
      <Alert className={cn('border-success/30 bg-success/5', className)}>
        <CheckCircle className="h-4 w-4 text-success" />
        <AlertTitle className="text-success">{t('scans.compat.allTitle')}</AlertTitle>
        <AlertDescription className="text-success/80">
          {t('scans.compat.allDesc', undefined, { total: preview.totalAssets, tool: toolName })}
        </AlertDescription>
      </Alert>
    )
  }

  const StatusIcon = status === 'partial' ? AlertTriangle : XCircle

  return (
    <Alert
      variant={status === 'none' ? 'destructive' : 'default'}
      className={cn(status === 'partial' && 'border-warning/30 bg-warning/5', className)}
    >
      <StatusIcon
        className={cn('h-4 w-4', status === 'partial' ? 'text-warning' : 'text-destructive')}
      />
      <AlertTitle className={cn(status === 'partial' ? 'text-warning' : 'text-destructive')}>
        {status === 'partial' ? t('scans.compat.someTitle') : t('scans.compat.noneTitle')}
      </AlertTitle>
      <AlertDescription className="space-y-3">
        <p className={cn(status === 'partial' ? 'text-warning/80' : 'text-destructive/80')}>
          {status === 'partial'
            ? t('scans.compat.someDesc', undefined, {
                incompatible: preview.incompatibleAssets,
                total: preview.totalAssets,
                tool: toolName,
              })
            : t('scans.compat.noneDesc', undefined, { total: preview.totalAssets, tool: toolName })}
        </p>

        {/* Progress bar showing compatibility */}
        <div className="space-y-1">
          <div className="flex justify-between text-xs">
            <span>{t('scans.compat.compatibility')}</span>
            <span>{Math.round(preview.compatibilityPercent)}%</span>
          </div>
          <Progress
            value={preview.compatibilityPercent}
            className={cn(
              'h-2',
              status === 'partial' && '[&>div]:bg-warning',
              status === 'none' && '[&>div]:bg-destructive'
            )}
          />
        </div>

        {/* Stats row */}
        <div className="flex gap-4 text-sm">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1">
                  <CheckCircle className="h-3.5 w-3.5 text-success" />
                  <span className="text-success">
                    {t('scans.compat.compatibleCount', undefined, {
                      count: preview.compatibleAssets,
                    })}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{t('scans.compat.willScan')}</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1">
                  <XCircle className="h-3.5 w-3.5 text-destructive" />
                  <span className="text-destructive">
                    {t('scans.compat.incompatibleCount', undefined, {
                      count: preview.incompatibleAssets,
                    })}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{t('scans.compat.willSkip')}</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

          {preview.unclassifiedAssets > 0 && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex items-center gap-1">
                    <Info className="h-3.5 w-3.5 text-slate-500" />
                    <span className="text-slate-500">
                      {t('scans.compat.unclassifiedCount', undefined, {
                        count: preview.unclassifiedAssets,
                      })}
                    </span>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p>{t('scans.compat.unclassifiedHint')}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>

        {/* Supported targets */}
        {preview.supportedTargets && preview.supportedTargets.length > 0 && (
          <div className="flex flex-wrap items-center gap-1 text-xs">
            <span className="text-muted-foreground">{t('scans.compat.supported')}</span>
            {preview.supportedTargets.map((target) => (
              <Badge key={target} variant="outline" className="text-xs">
                {target}
              </Badge>
            ))}
          </div>
        )}

        {/* Detailed breakdown (collapsible) */}
        {showDetails && preview.assetTypeBreakdown && preview.assetTypeBreakdown.length > 0 && (
          <Collapsible open={isOpen} onOpenChange={setIsOpen}>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm" className="h-7 px-2 text-xs">
                <ChevronDown
                  className={cn('me-1 h-3 w-3 transition-transform', isOpen && 'rotate-180')}
                />
                {isOpen ? t('scans.compat.hideBreakdown') : t('scans.compat.showBreakdown')}
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="mt-2">
              <div className="rounded-md border bg-background/50 p-2">
                {/* A few-row breakdown inside an alert, not a list: a plain table keeps
                    it compact; DataTable's toolbar and paging would outweigh it. */}
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b text-muted-foreground">
                      <th className="pb-1 text-start font-medium">{t('scans.compat.colType')}</th>
                      <th className="pb-1 text-end font-medium">{t('scans.compat.colCount')}</th>
                      <th className="pb-1 text-end font-medium">{t('scans.compat.colStatus')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {preview.assetTypeBreakdown.map((item) => (
                      <tr key={item.assetType}>
                        <td className="py-1">
                          {ASSET_TYPE_LABELS[item.assetType as keyof typeof ASSET_TYPE_LABELS] ||
                            item.assetType}
                        </td>
                        <td className="py-1 text-end tabular-nums">{item.count}</td>
                        <td className="py-1 text-end">
                          {item.isCompatible ? (
                            <Badge
                              variant="outline"
                              className="border-success/30 bg-success/10 text-success"
                            >
                              {t('scans.compat.compatible')}
                            </Badge>
                          ) : (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Badge
                                    variant="outline"
                                    className="border-destructive/30 bg-destructive/10 text-destructive"
                                  >
                                    {t('scans.compat.skipped')}
                                  </Badge>
                                </TooltipTrigger>
                                {item.reason && (
                                  <TooltipContent>
                                    <p>{item.reason}</p>
                                  </TooltipContent>
                                )}
                              </Tooltip>
                            </TooltipProvider>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CollapsibleContent>
          </Collapsible>
        )}
      </AlertDescription>
    </Alert>
  )
}
