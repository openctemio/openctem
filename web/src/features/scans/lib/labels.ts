import {
  SCAN_CONFIG_STATUS_LABELS,
  SCAN_TYPE_LABELS,
  SCHEDULE_TYPE_LABELS,
  type ScanConfig,
} from '@/lib/api/scan-types'
import type { Translate } from './translate'

/** Display names of the API's scan enums, in the active language. */
export const scanTypeName = (t: Translate, type: ScanConfig['scan_type']) =>
  t(`scans.scanType.${type}`, SCAN_TYPE_LABELS[type])

export const scheduleTypeName = (t: Translate, type: ScanConfig['schedule_type']) =>
  t(`scans.scheduleType.${type}`, SCHEDULE_TYPE_LABELS[type])

export const configStatusName = (t: Translate, status: ScanConfig['status']) =>
  t(`scans.configStatus.${status}`, SCAN_CONFIG_STATUS_LABELS[status])
