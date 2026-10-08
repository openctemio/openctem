/**
 * CSV export of the inventory as filtered (research/77): every matching asset,
 * not just the page on screen, with the core columns and, for a one-type
 * list, that type's attributes. The rows come from the same data-scoped list
 * endpoint as the table; cells go through exportToCsv's formula guard.
 */
import { toast } from 'sonner'
import { exportToCsv, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { propertyLabel } from '@/features/asset-types/lib/property-schema'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import { fetchAllAssets, type AssetSearchFilters } from '../hooks/use-assets'
import type { Asset } from '../types'
import { attributeText } from './attribute-value'

/** The CSV columns: core fields, then the type's attributes (not objects). */
export function inventoryExportFields(view: TypeView | null): ExportFieldConfig<Asset>[] {
  const core: ExportFieldConfig<Asset>[] = [
    { header: 'Name', accessor: (a) => a.name },
    { header: 'Type', accessor: (a) => a.type },
    { header: 'Sub-type', accessor: (a) => a.subType ?? '' },
    { header: 'Criticality', accessor: (a) => a.criticality },
    { header: 'Exposure', accessor: (a) => a.exposure },
    { header: 'Status', accessor: (a) => a.status },
    { header: 'Owner', accessor: (a) => a.primaryOwner?.name ?? a.ownerRef ?? '' },
    { header: 'Risk score', accessor: (a) => a.riskScore },
    { header: 'Findings', accessor: (a) => a.findingCount },
    { header: 'Last seen', accessor: (a) => a.lastSeen },
    { header: 'Labels', accessor: (a) => (a.tags ?? []).join('; ') },
  ]
  const attributes = (view?.attributes ?? [])
    .filter((a) => a.kind !== 'object')
    .map((a): ExportFieldConfig<Asset> => ({
      header: propertyLabel(a.key),
      accessor: (asset) => attributeText(asset, a.key),
    }))
  return [...core, ...attributes]
}

/** Fetches every asset the filters match and downloads them as CSV. */
export async function exportInventory(
  filters: AssetSearchFilters,
  view: TypeView | null
): Promise<void> {
  const { page: _page, pageSize: _pageSize, ...rest } = filters
  const rows = await fetchAllAssets(rest, (loaded) =>
    toast.warning(
      `Export limited to the first ${loaded.toLocaleString()} assets: narrow the filters to export the rest`
    )
  )
  const name = view ? view.plural.toLowerCase().replace(/[^a-z0-9]+/g, '-') : 'assets'
  exportToCsv(rows, inventoryExportFields(view), name)
}
