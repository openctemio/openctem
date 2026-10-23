'use client'

import { useTranslation } from '@/context/i18n-provider'

export function SkipToMain() {
  const { t } = useTranslation()
  return (
    <a
      className={`bg-primary text-primary-foreground hover:bg-primary/90 focus-visible:ring-ring fixed start-44 z-999 -translate-y-52 px-4 py-2 text-sm font-medium whitespace-nowrap opacity-95 shadow-sm transition focus:translate-y-3 focus:transform focus-visible:ring-1`}
      href="#content"
    >
      {t('nav.header.skipToMain', 'Skip to main content')}
    </a>
  )
}
