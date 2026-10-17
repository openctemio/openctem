'use client'

import * as React from 'react'
import { Layers } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared'

import { useAssetTechnologies } from '../../hooks/use-asset-technologies'
import type { Asset } from '../../types'
import { TechnologiesByCategory, type TechnologyChipData } from './technologies-by-category'

/**
 * The asset Overview's "Technologies" section (RFC-112): what probes
 * detected, as chips grouped by category with the version when known. The
 * chips render from the technologies the asset response embeds; the
 * technologies endpoint adds confidence, source and last seen to their
 * tooltips. Hidden when nothing was detected.
 */
export function AssetTechnologiesSection({
  asset,
  onViewAll,
}: {
  asset: Asset
  onViewAll?: () => void
}) {
  const { t } = useTranslation()
  const embedded = React.useMemo(() => asset.technologies ?? [], [asset.technologies])
  const { data } = useAssetTechnologies(embedded.length > 0 ? asset.id : null)
  const list: TechnologyChipData[] = React.useMemo(
    () => (data && data.length > 0 ? data : embedded),
    [data, embedded]
  )
  if (list.length === 0) return null
  return (
    <DetailSection
      title={t('assets.technologies.title', 'Technologies')}
      icon={Layers}
      count={list.length}
      actions={
        onViewAll && (
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={onViewAll}>
            {t('assets.technologies.viewAll', 'View all')}
          </Button>
        )
      }
    >
      <TechnologiesByCategory technologies={list} />
    </DetailSection>
  )
}
