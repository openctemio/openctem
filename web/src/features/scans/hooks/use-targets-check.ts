'use client'

/**
 * The scope check of a scan form's targets, shared by the Targets step (which
 * shows it) and the wizard dialogs (which gate Next on it): the same debounced
 * request with the same options, so SWR sends it once. The server is the only
 * authority; this reads its answer.
 */

import { useMemo } from 'react'
import { useDebounce } from '@/hooks/use-debounce'
import { useScopeCheck } from '@/features/scope'
import type { NewScanFormData } from '../types'
import { directTargets } from '../lib/scan-form'
import { scopeCheckTier } from '../lib/scan-intensity'
import {
  scanReadiness,
  SUMMARY_SCOPE_DEBOUNCE_MS,
  type ScanReadiness,
} from '../components/target-picker/selection-summary'

const UNKNOWN: ScanReadiness = { state: 'unknown', scannable: 0, unresolved: [], refused: 0 }

export type SensorPreferenceOption = 'auto' | 'tenant' | 'platform'

export function sensorPreferenceOf(data: Pick<NewScanFormData, 'sensorPreference'>) {
  return data.sensorPreference === 'tenant' || data.sensorPreference === 'platform'
    ? data.sensorPreference
    : ('auto' as SensorPreferenceOption)
}

export function useTargetsCheck(data: NewScanFormData, enabled = true) {
  const sent = directTargets(data)
  const joined = useDebounce(sent.join('\n'), SUMMARY_SCOPE_DEBOUNCE_MS)
  const list = useMemo(() => (joined ? joined.split('\n') : []), [joined])
  const sensorPreference = sensorPreferenceOf(data)
  const check = useScopeCheck(list, {
    enabled,
    sensor_preference: sensorPreference,
    scanner_name: data.mode === 'single' ? data.scannerName || undefined : undefined,
    tier: scopeCheckTier(data),
  })
  const groupCount = data.targets.assetGroupIds.length
  // Keyed on the current target text: an answer about an older selection
  // (the check is debounced) reads as unknown and never blocks.
  const sentKey = sent.join('\n')
  const readiness = useMemo(
    () =>
      check.available && enabled
        ? scanReadiness(sentKey ? sentKey.split('\n') : [], check.resultFor, groupCount)
        : UNKNOWN,
    [check.available, check.resultFor, sentKey, groupCount, enabled]
  )
  return { check, readiness, sent, sensorPreference }
}
