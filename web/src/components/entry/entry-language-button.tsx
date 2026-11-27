'use client'

import type { ComponentProps } from 'react'
import { Languages } from 'lucide-react'

import { TEXT_LINK_CLASS } from '@/components/ui/text-link-class'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The footer's language button: drawn as one more footer link (same size and
 * colour as the legal links), not a button of its own size. Also the
 * placeholder EntryFrame shows while the menu's code loads, so the footer does
 * not move when the menu arrives.
 */
export function EntryLanguageButton({ className, ...props }: ComponentProps<'button'>) {
  const { t } = useTranslation()
  return (
    <button
      type="button"
      data-slot="entry-language"
      className={cn(
        TEXT_LINK_CLASS.nav,
        'inline-flex items-center gap-1 rounded-sm focus-visible:outline-2 focus-visible:outline-ring',
        className
      )}
      {...props}
    >
      <Languages className="size-3.5" aria-hidden />
      {t('common.language', 'Language')}
    </button>
  )
}
