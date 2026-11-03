'use client'

import { useCallback } from 'react'
import { useTranslation } from '@/context/i18n-provider'

/**
 * A module's name and description in the reader's language:
 * `settings.modules.item.<id>.{name,description}`, falling back to the
 * registry text the API sends (English) for a module the catalog does not
 * know yet.
 */
export function useModuleText() {
  const { t } = useTranslation()
  const name = useCallback(
    (id: string, fallback?: string) => t(`settings.modules.item.${id}.name`, fallback ?? id),
    [t]
  )
  const description = useCallback(
    (id: string, fallback?: string) => t(`settings.modules.item.${id}.description`, fallback ?? ''),
    [t]
  )
  return { name, description }
}
