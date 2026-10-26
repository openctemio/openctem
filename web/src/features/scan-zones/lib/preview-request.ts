import type { CreateScanConfigRequest } from '@/lib/api/scan-types'
import type { ScanZonePreviewRequest } from '@/lib/api/scan-zone-types'

/** The routing preview request for a scan as the New/Edit dialog would save it. */
export function toZonePreviewRequest(
  r: Pick<
    CreateScanConfigRequest,
    | 'targets'
    | 'asset_group_ids'
    | 'scan_type'
    | 'scanner_name'
    | 'scan_workflow_id'
    | 'targets_per_job'
    | 'target_options'
  >,
  scanZoneId: string | null | undefined
): ScanZonePreviewRequest {
  return {
    targets: r.targets ?? [],
    asset_group_ids: r.asset_group_ids ?? [],
    scan_type: r.scan_type,
    scanner_name: r.scanner_name,
    scan_workflow_id: r.scan_workflow_id,
    targets_per_job: r.targets_per_job,
    scan_zone_id: scanZoneId ?? null,
    ...(r.target_options && Object.keys(r.target_options).length > 0
      ? { target_options: r.target_options }
      : {}),
  }
}
