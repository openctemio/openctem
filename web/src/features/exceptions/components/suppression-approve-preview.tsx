'use client'

import { AlertTriangle, Info, Loader2 } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { useSuppressionPreview } from '../api/use-suppressions-api'

/**
 * What approving a suppression rule does to existing findings: the open
 * findings it matches are closed with the rule's disposition. Shown in the
 * approve dialog; `ruleId` is passed only while the dialog is open.
 */
export function SuppressionApprovePreview({ ruleId }: { ruleId: string | undefined }) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useSuppressionPreview(ruleId)

  if (isLoading) {
    return (
      <p className="text-muted-foreground flex items-center gap-2 text-sm" role="status">
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
        {t('confirm.suppression.previewLoading', 'Counting the open findings this rule matches…')}
      </p>
    )
  }

  if (error || !data) {
    return (
      <Alert variant="destructive">
        <AlertTriangle aria-hidden />
        <AlertDescription>
          {t(
            'confirm.suppression.previewError',
            'Could not count the open findings this rule matches. Approving still closes them.'
          )}
        </AlertDescription>
      </Alert>
    )
  }

  const count = data.matching_open_findings
  let text: string
  if (data.capped) {
    text = t(
      'confirm.suppression.previewCapped',
      'More than {limit} open findings match. This approval closes {limit} of them; the rest stay open.',
      { limit: data.limit.toLocaleString() }
    )
  } else if (count === 0) {
    text = t(
      'confirm.suppression.previewNone',
      'No open findings match this rule now. It applies to new findings as they arrive.'
    )
  } else if (count === 1) {
    text = t('confirm.suppression.previewOne', 'This will close 1 open finding.')
  } else {
    text = t('confirm.suppression.previewMany', 'This will close {count} open findings.', {
      count: count.toLocaleString(),
    })
  }

  return (
    <Alert data-testid="suppression-approve-preview">
      <Info aria-hidden />
      <AlertDescription>{text}</AlertDescription>
    </Alert>
  )
}
