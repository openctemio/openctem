'use client'

/**
 * Bug-bounty program provenance of an asset (RFC-065 §16.5): a "Program
 * target" badge with the program, its platform and whether its terms are
 * accepted, from the system tags the platform derives (never editable). An
 * asset without program links renders nothing.
 */

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { programTargetInfo } from '../lib/program-tags'

interface ProgramTargetBadgeProps {
  systemTags?: string[]
  programOnly?: boolean
}

export function ProgramTargetBadge({ systemTags, programOnly }: ProgramTargetBadgeProps) {
  const { t } = useTranslation()
  const info = programTargetInfo(systemTags)
  if (!info) return null
  const programs = info.programs.join(', ')
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <Badge
        variant="outline"
        className="border-dashed border-amber-500/60 text-amber-700 dark:text-amber-300"
        title={t(
          'assets.programTarget.title',
          'Listed by a bug-bounty program. Tags from programs are set by the platform and cannot be edited.'
        )}
      >
        {t('assets.programTarget.badge', 'Program target')}
        {programs ? `: ${programs}` : ''}
      </Badge>
      {info.unattested && (
        <Badge variant="secondary">
          {t('assets.programTarget.unattested', 'terms not accepted')}
        </Badge>
      )}
      {programOnly && (
        <Badge variant="secondary">
          {t('assets.programTarget.programOnly', 'not in your own scope')}
        </Badge>
      )}
    </span>
  )
}
