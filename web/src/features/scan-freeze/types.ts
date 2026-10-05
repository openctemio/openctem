/**
 * Scan freeze windows (api docs/architecture/scan-zones.md, "Freeze
 * windows"). Wire types come from the generated OpenAPI types.
 */
import type { components } from '@/lib/api/generated/api.types'

type S = components['schemas']

export type FreezeWindow = S['internal_infra_http_handler.ScanFreezeWindowResponse']
export type FreezeWindowList = S['internal_infra_http_handler.ScanFreezeWindowListResponse']
export type CreateFreezeWindowRequest =
  S['internal_infra_http_handler.CreateScanFreezeWindowRequest']
export type UpdateFreezeWindowRequest =
  S['internal_infra_http_handler.UpdateScanFreezeWindowRequest']

export type FreezeRecurrence = 'once' | 'weekly'
