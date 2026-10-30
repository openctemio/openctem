'use client'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

export type ScopeConfirmKind = 'approve' | 'activate' | 'renew'

/**
 * The confirmation before a scope entry is approved, put in effect or renewed:
 * each one changes what scans may reach, so it names the entry and the effect
 * first.
 */
export function ScopeActionConfirm({
  kind,
  pattern,
  days,
  open,
  onOpenChange,
  onConfirm,
  isLoading,
}: {
  kind: ScopeConfirmKind
  pattern?: string
  /** For renew: how many days the entry stays in effect. */
  days?: number
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => unknown
  isLoading?: boolean
}) {
  const { t } = useTranslation()
  const name = pattern || t('scope.fix.thisEntry', 'this entry')
  const copy = {
    approve: {
      title: t('confirm.scopeFix.approveTitle', 'Approve {pattern}?', { pattern: name }),
      desc: t(
        'confirm.scopeFix.approveDesc',
        'Your approval counts toward the change. Once the approvals it needs are complete, it applies to your scope and scans follow it.'
      ),
      button: t('confirm.scopeFix.approveButton', 'Approve'),
    },
    activate: {
      title: t('confirm.scopeFix.activateTitle', 'Put {pattern} in effect now?', {
        pattern: name,
      }),
      desc: t(
        'confirm.scopeFix.activateDesc',
        'The entry takes effect now, so scans can reach what it covers. You can deactivate it later.'
      ),
      button: t('confirm.scopeFix.activateButton', 'Put in effect'),
    },
    renew: {
      title: t('confirm.scopeFix.renewTitle', 'Renew the entry {pattern}?', { pattern: name }),
      desc: t(
        'confirm.scopeFix.renewDesc',
        'The entry stays in effect for {days} more days, so scans can keep reaching what it covers.',
        { days: days ?? 7 }
      ),
      button: t('confirm.scopeFix.renewButton', 'Renew entry'),
    },
  }[kind]
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={copy.title}
      desc={copy.desc}
      confirmText={copy.button}
      isLoading={isLoading}
      handleConfirm={onConfirm}
    />
  )
}
