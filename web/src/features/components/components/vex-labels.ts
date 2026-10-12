'use client'

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'

/** Translated labels of VEX statuses, justifications and version modes. */
export function useVexLabels() {
  const { t } = useTranslation()
  return useMemo(
    () => ({
      status: (s: string) =>
        ({
          not_affected: t('components.vex.status.not_affected', 'Not affected'),
          affected: t('components.vex.status.affected', 'Affected'),
          fixed: t('components.vex.status.fixed', 'Fixed'),
          under_investigation: t(
            'components.vex.status.under_investigation',
            'Under investigation'
          ),
        })[s] ?? s,
      justification: (j: string) =>
        ({
          component_not_present: t(
            'components.vex.just.component_not_present',
            'Component not present'
          ),
          vulnerable_code_not_present: t(
            'components.vex.just.vulnerable_code_not_present',
            'Vulnerable code not present'
          ),
          vulnerable_code_not_in_execute_path: t(
            'components.vex.just.vulnerable_code_not_in_execute_path',
            'Vulnerable code not in execute path'
          ),
          vulnerable_code_cannot_be_controlled_by_adversary: t(
            'components.vex.just.vulnerable_code_cannot_be_controlled_by_adversary',
            'Vulnerable code cannot be controlled by an adversary'
          ),
          inline_mitigations_already_exist: t(
            'components.vex.just.inline_mitigations_already_exist',
            'Inline mitigations already exist'
          ),
        })[j] ?? j,
      versionMode: (m: string) =>
        ({
          all: t('components.vex.mode.all', 'Every version'),
          list: t('components.vex.mode.list', 'Listed versions'),
          range: t('components.vex.mode.range', 'Version range'),
        })[m] ?? m,
    }),
    [t]
  )
}
