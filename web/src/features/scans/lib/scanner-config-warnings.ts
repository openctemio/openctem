import { toast } from 'sonner'

import type { ScanConfig, ScannerConfigWarning } from '@/lib/api/scan-types'
import { enTranslate, type Translate } from './translate'

const REASON_KEYS: Record<string, string> = {
  key_name: 'scans.secretWarn.keyName',
  known_format: 'scans.secretWarn.knownFormat',
  high_entropy: 'scans.secretWarn.highEntropy',
}

/**
 * One line per scanner_config value the API flagged as secret-looking
 * (api RFC-032 Phase 0). The value itself is never in the response.
 */
export function describeScannerConfigWarnings(
  warnings: ScannerConfigWarning[] | undefined,
  t: Translate = enTranslate
): string[] {
  if (!warnings?.length) return []
  return warnings.map(
    (w) => `${w.path}: ${REASON_KEYS[w.reason] ? t(REASON_KEYS[w.reason]) : w.reason}`
  )
}

/**
 * Warn after a scan was saved when its scanner config holds values that look
 * like secrets: the config is sent to the sensor in clear inside every scan
 * command. Never blocks; the scan is already saved.
 */
export function notifyScannerConfigWarnings(
  scan: Pick<ScanConfig, 'name' | 'scanner_config_warnings'> | undefined,
  t: Translate = enTranslate
) {
  const lines = describeScannerConfigWarnings(scan?.scanner_config_warnings, t)
  if (!lines.length) return
  toast.warning(t('scans.secretWarn.title', undefined, { name: scan?.name ?? '' }), {
    description: t('scans.secretWarn.detail', undefined, { lines: lines.join('; ') }),
    duration: 10000,
  })
}
