'use client'

import { Archive } from 'lucide-react'

import Link from '@/components/link'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanWorkflow } from '@/lib/api'
import { retiredInfo } from '../lib/retired'

type RetiredFields = Pick<ScanWorkflow, 'is_retired' | 'superseded_by' | 'based_on_retired'>

/** "Retired" status badge; its tooltip says what replaced the workflow. */
export function RetiredBadge({ workflow }: { workflow: RetiredFields }) {
  const { t } = useTranslation()
  const replacement = workflow.superseded_by
  return (
    <Badge
      variant="secondary"
      title={
        replacement
          ? t('scans.workflows.retiredReplacedBy', 'Retired, replaced by {name}', {
              name: replacement.name,
            })
          : t('scans.workflows.retiredNoReplacement', 'Retired, no direct replacement')
      }
    >
      {t('scans.workflows.statusRetired', 'Retired')}
    </Badge>
  )
}

/**
 * Explains a retired workflow, or a copy made from one, and links the
 * replacement. Nothing renders for any other workflow.
 */
export function RetiredNotice({ workflow }: { workflow: RetiredFields }) {
  const { t } = useTranslation()
  const info = retiredInfo(workflow)
  if (!info) return null
  const replacement = info.replacement
  const body =
    info.kind === 'retired'
      ? t(
          'scans.workflows.retiredNoticeBody',
          'It no longer starts new scans and cannot be copied. Scans and copies already made from it keep working.'
        )
      : replacement
        ? t(
            'scans.workflows.basedOnBody',
            'This workflow was made from {source}, which is retired and replaced by {name}. It keeps working.',
            { source: info.source ?? '', name: replacement.name }
          )
        : t(
            'scans.workflows.basedOnBodyNone',
            'This workflow was made from {source}, which is retired. It keeps working.',
            { source: info.source ?? '' }
          )
  return (
    <Alert data-testid="retired-notice">
      <Archive className="h-4 w-4" />
      <AlertTitle>
        {info.kind === 'retired'
          ? t('scans.workflows.retiredNoticeTitle', 'This workflow is retired')
          : t('scans.workflows.basedOnTitle', 'Based on a retired template')}
      </AlertTitle>
      <AlertDescription className="space-y-1">
        <p>{body}</p>
        {replacement && (
          <p>
            <Link
              href={`/scans/workflows/${replacement.id}`}
              className="font-medium underline underline-offset-2"
            >
              {t('scans.workflows.openReplacement', 'Open {name}', { name: replacement.name })}
            </Link>
          </p>
        )}
      </AlertDescription>
    </Alert>
  )
}
