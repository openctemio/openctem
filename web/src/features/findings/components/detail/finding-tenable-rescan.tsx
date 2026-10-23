'use client'

/**
 * "Rescan with Tenable.sc" on a finding the Tenable.sc connector reported: its
 * asset is scanned now through the connector (POST
 * /integrations/{id}/scans/run). Nothing closes the finding directly: a full
 * rescan that no longer reports it closes it through coverage auto-resolve,
 * when the organization enforces it. Shown next to the retest section, only
 * with scans:write and a connector to scan with.
 */

import { ScanSearch } from 'lucide-react'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import {
  TenableScanNowButton,
  useScanNowConnectors,
} from '@/features/integrations/components/scanners/tenable-scan-now'
import { isTenableSCFinding } from '@/features/integrations/lib/tenable-sc'
import { useTranslation } from '@/context/i18n-provider'

interface FindingTenableRescanProps {
  finding: { toolName?: string; source?: string; assets?: { id: string }[] }
  className?: string
}

export function FindingTenableRescanSection({ finding, className }: FindingTenableRescanProps) {
  const assetId = finding.assets?.[0]?.id
  // Only a Tenable.sc finding with an asset can be rescanned: any other
  // finding never asks for the connector list (one request saved per load).
  if (!isTenableSCFinding(finding) || !assetId) return null
  return <TenableRescan assetId={assetId} className={className} />
}

function TenableRescan({ assetId, className }: { assetId: string; className?: string }) {
  const { t } = useTranslation()
  const connectors = useScanNowConnectors()
  if (connectors.length === 0) return null

  return (
    <DetailSection
      title={t('findings.tenableRescan.title', 'Rescan with Tenable.sc')}
      icon={ScanSearch}
      className={className}
      actions={
        <TenableScanNowButton
          assetIds={[assetId]}
          className="h-7"
          label={t('findings.tenableRescan.now', 'Rescan')}
          title={t(
            'findings.tenableRescan.nowTitle',
            "Scan this finding's asset now through the Tenable.sc connector"
          )}
        />
      }
    >
      <p className="text-sm text-muted-foreground">
        {t(
          'findings.tenableRescan.help',
          'After a fix, rescan the asset with Tenable.sc. When the organization enforces coverage auto-resolve, the finding closes automatically once a full rescan no longer reports it.'
        )}
      </p>
    </DetailSection>
  )
}
