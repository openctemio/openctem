'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'

/** "22 Nov 2026" in the viewer's language. */
export function formatDay(value: string | null | undefined, locale: string): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString(locale, { day: 'numeric', month: 'short', year: 'numeric' })
}

/** Who published or approved: "you" for the viewer, else the name the API sent, else the id. */
export function usePersonName() {
  const { t } = useTranslation()
  const me = useDisplayUser()
  return (id: string | null | undefined, name?: string | null): string => {
    if (!id) return '—'
    if (me?.id && id === me.id) return t('automations.version.you', 'you')
    return name || id
  }
}
