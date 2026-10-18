'use client'

import { useSettingsAnchorHighlight } from '@/hooks/use-settings-anchor-highlight'

/** Mounted once in the dashboard layout: see useSettingsAnchorHighlight. */
export function SettingsAnchorHighlighter() {
  useSettingsAnchorHighlight()
  return null
}
