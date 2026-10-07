'use client'

import { useCallback } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_LABEL_KEYS, SEVERITY_LABELS, type SeverityLevel } from '@/lib/severity'
import {
  CRITICALITY_LABEL_KEYS,
  CRITICALITY_LABELS,
  type CriticalityLevel,
} from '@/lib/criticality'

/** Localised severity label: `const label = useSeverityLabel(); label('info')`. */
export function useSeverityLabel(): (s: SeverityLevel) => string {
  const { t } = useTranslation()
  return useCallback((s: SeverityLevel) => t(SEVERITY_LABEL_KEYS[s], SEVERITY_LABELS[s]), [t])
}

/** Localised criticality label (`none` reads "Not rated"). */
export function useCriticalityLabel(): (c: CriticalityLevel) => string {
  const { t } = useTranslation()
  return useCallback(
    (c: CriticalityLevel) => t(CRITICALITY_LABEL_KEYS[c], CRITICALITY_LABELS[c]),
    [t]
  )
}
