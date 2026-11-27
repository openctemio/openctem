import type { ExportFieldConfig } from '@/hooks/use-csv-export'
import type { useTranslation } from '@/context/i18n-provider'
import type { AssetGroup } from '@/features/asset-groups/types'

type Translate = ReturnType<typeof useTranslation>['t']

/** The columns of the asset groups CSV export, in the viewer language. */
export function assetGroupExportFields(t: Translate): ExportFieldConfig<AssetGroup>[] {
  return [
    { header: t('assetGroups.csv.name', 'Name'), accessor: (g) => g.name },
    {
      header: t('assetGroups.csv.description', 'Description'),
      accessor: (g) => g.description ?? '',
    },
    { header: t('assetGroups.csv.environment', 'Environment'), accessor: (g) => g.environment },
    { header: t('assetGroups.csv.criticality', 'Criticality'), accessor: (g) => g.criticality },
    {
      header: t('assetGroups.csv.businessUnit', 'Business unit'),
      accessor: (g) => g.businessUnit ?? '',
    },
    { header: t('assetGroups.csv.owner', 'Owner'), accessor: (g) => g.owner ?? '' },
    { header: t('assetGroups.csv.assets', 'Assets'), accessor: (g) => g.assetCount },
    { header: t('assetGroups.csv.findings', 'Findings'), accessor: (g) => g.findingCount },
    { header: t('assetGroups.csv.riskScore', 'Risk score'), accessor: (g) => g.riskScore },
    { header: t('assetGroups.csv.tags', 'Tags'), accessor: (g) => (g.tags ?? []).join('; ') },
  ]
}
