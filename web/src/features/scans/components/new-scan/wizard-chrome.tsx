'use client'

/**
 * The unsaved-changes prompt behind the close button of New scan and Edit
 * scan: the shared dialog leave guard with the scan wizard's words. With
 * `keep`, the question also offers "Keep as draft", which closes and keeps
 * the draft for the next open.
 */

import { useTranslation } from '@/context/i18n-provider'
import { useDiscardPrompt as useSharedDiscardPrompt } from '@/features/shared/components/forms'

export function useDiscardPrompt(isDirty: () => boolean, close: () => void, keep?: () => void) {
  const { t } = useTranslation()
  return useSharedDiscardPrompt(isDirty, close, {
    keep,
    keepTitle: t('scans.wizard.closeTitle'),
    keepDescription: t('scans.wizard.closeDesc'),
    keepLabel: t('scans.wizard.keepDraft'),
  })
}
