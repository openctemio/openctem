'use client'

import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { useAdminAuditChain, type AdminAuditChainBreak } from '../api/use-admin-audit'

/**
 * Whether the administrators' audit log is intact: the log is append-only
 * and every row is hash-chained, so an edited, unlinked or missing row shows
 * here. Shown above Security > Activity.
 */
export function AdminAuditChainStatus() {
  const { t } = useTranslation()
  const { data, error, isLoading } = useAdminAuditChain()

  // While the chain is checked, the intact state is drawn with its text kept
  // invisible: the same height at every width and language, so the list below
  // does not move when the answer arrives (a skeleton was 4 to 24 px shorter).
  if (isLoading) {
    return (
      <Alert aria-busy="true" data-testid="audit-chain-loading">
        <ShieldCheck className="invisible size-4" aria-hidden />
        <AlertTitle className="invisible" aria-hidden>
          {t('admin.auditChain.okTitle', 'Audit log intact')}
        </AlertTitle>
        <AlertDescription className="invisible" aria-hidden>
          {t(
            'admin.auditChain.okBody',
            'All {count} entries verify: none was changed or removed since it was written.',
            { count: '0000' }
          )}
        </AlertDescription>
      </Alert>
    )
  }
  if (error || !data) {
    return (
      <Alert>
        <ShieldAlert className="size-4" />
        <AlertDescription>
          {t('admin.auditChain.unavailable', 'The audit chain could not be checked right now.')}
        </AlertDescription>
      </Alert>
    )
  }
  const reason = (b: AdminAuditChainBreak) =>
    b.reason === 'changed'
      ? t('admin.auditChain.reasonChanged', 'changed after it was written')
      : b.reason === 'gap'
        ? t('admin.auditChain.reasonGap', 'rows are missing before it')
        : t('admin.auditChain.reasonLink', 'does not follow the row before it')

  if (data.breaks.length === 0) {
    return (
      <Alert>
        <ShieldCheck className="size-4" />
        <AlertTitle>{t('admin.auditChain.okTitle', 'Audit log intact')}</AlertTitle>
        <AlertDescription>
          {t(
            'admin.auditChain.okBody',
            'All {count} entries verify: none was changed or removed since it was written.',
            { count: data.entries }
          )}
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive">
      <ShieldAlert className="size-4" />
      <AlertTitle>{t('admin.auditChain.brokenTitle', 'Audit log tampered with')}</AlertTitle>
      <AlertDescription>
        <p>
          {t(
            'admin.auditChain.brokenBody',
            '{count} entries do not verify. Treat this as a security incident: compare with your off-site copy of the log.',
            { count: data.breaks.length }
          )}
        </p>
        <ul className="mt-2 list-disc ps-5 font-mono text-xs">
          {data.breaks.slice(0, 10).map((b) => (
            <li key={`${b.position}-${b.id}`}>
              #{b.position} {b.id}: {reason(b)}
            </li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  )
}
