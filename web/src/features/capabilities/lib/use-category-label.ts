'use client'

import { useCallback } from 'react'

import { useTranslation } from '@/context/i18n-provider'

/**
 * The name of a capability category in the person's language. A category
 * without a translation shows as plain sentence-case words, never the raw key.
 */
export function useCategoryLabel() {
  const { t } = useTranslation()
  return useCallback(
    (category: string): string => {
      const words = category
        .replace(/[-_.]+/g, ' ')
        .trim()
        .toLowerCase()
      const plain = words.charAt(0).toUpperCase() + words.slice(1)
      return t(`scans.capabilities.category.${category.toLowerCase()}`, plain)
    },
    [t]
  )
}
