'use client'

import { KevBadge as KevMark } from '@/components/ui/kev-badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import type { CISAKEVData } from '../types'

interface KEVBadgeProps {
  kev?: CISAKEVData
  className?: string
}

export function KEVBadge({ kev, className }: KEVBadgeProps) {
  const { t } = useTranslation()
  if (!kev) return null
  const ransomware = !!kev.ransomware_use && kev.ransomware_use !== 'Unknown'

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <KevMark pastDue={kev.is_past_due} className={className} />
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        <div className="space-y-1 text-xs">
          <p className="font-semibold">
            {t('findings.list.kevTitle', 'CISA Known Exploited Vulnerability')}
          </p>
          <p>
            {t('findings.kev.added', 'Added: {date}', {
              date: new Date(kev.date_added).toLocaleDateString(),
            })}
          </p>
          <p>
            {t('findings.kev.due', 'Due: {date}', {
              date: new Date(kev.due_date).toLocaleDateString(),
            })}
            {kev.is_past_due && (
              <span className="ms-1 font-bold">{t('findings.kev.pastDue', '(past due)')}</span>
            )}
          </p>
          {ransomware && (
            <p>
              {t('findings.kev.ransomwareUse', 'Ransomware use: {value}', {
                value: kev.ransomware_use ?? '',
              })}
            </p>
          )}
          {kev.notes && <p className="mt-1 italic opacity-90">{kev.notes}</p>}
        </div>
      </TooltipContent>
    </Tooltip>
  )
}
