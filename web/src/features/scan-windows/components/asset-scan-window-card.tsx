'use client'

/**
 * The asset page's "Scan window": whether active scans of the asset may run
 * now, when they may next, or that they never can, and the windows that
 * apply. Hidden when no window applies, when the caller cannot read scans,
 * and when the API does not answer (an asset outside the caller's data
 * scope is 404).
 */

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, usePermissions } from '@/lib/permissions'

import { useWindowDecisions } from '../api/use-scan-windows'
import { WindowExplanation } from './window-decision'

export function AssetScanWindowCard({
  assetId,
  className,
}: {
  assetId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { data } = useWindowDecisions({ asset_ids: [assetId], tier: 1 }, can(Permission.ScansRead))
  const decision = data?.data?.find((d) => d.asset_id === assetId) ?? data?.data?.[0]
  if (!decision?.governed) return null
  return (
    <Card className={className} data-testid="asset-scan-window">
      <CardHeader>
        <CardTitle>{t('scanWindows.asset.title', 'Scan window')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        <p className="text-xs text-muted-foreground">
          {t('scanWindows.asset.hint', 'For active scans of this asset.')}
        </p>
        <WindowExplanation decision={decision} showGoverning />
      </CardContent>
    </Card>
  )
}
