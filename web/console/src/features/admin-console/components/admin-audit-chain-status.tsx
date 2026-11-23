'use client'

import type { ReactNode } from 'react'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { useAdminAuditChain, type AdminAuditChainBreak } from '../api/use-admin-audit'

/**
 * Whether the administrators' audit log is intact: the log is append-only
 * and every row is hash-chained, so an edited, unlinked or missing row shows
 * here. Security > Activity draws it in two places:
 *
 * - `AdminAuditChainBadge`, in the page header: one line that says the log is
 *   intact (its full sentence on hover and to assistive technology), or that
 *   it could not be checked, or that it was tampered with. It never takes a
 *   row of its own above the list.
 * - `AdminAuditChainStatus`, above the list, only when entries do not verify:
 *   a security incident is said in full, with every entry that breaks.
 */
export function AdminAuditChainBadge() {
  const { t } = useTranslation()
  const { data, error, isLoading } = useAdminAuditChain()

  // While the chain is checked the line keeps its place with its text
  // invisible, so the header does not move when the answer arrives.
  if (isLoading) {
    return (
      <ChainLine testId="audit-chain-loading" busy>
        <ShieldCheck className="invisible size-4 shrink-0" aria-hidden />
        <span className="invisible" aria-hidden>
          {t('admin.auditChain.okTitle', 'Audit log intact')}
        </span>
      </ChainLine>
    )
  }
  if (error || !data) {
    const text = t(
      'admin.auditChain.unavailable',
      'The audit chain could not be checked right now.'
    )
    return (
      <ChainLine testId="audit-chain-unavailable" hint={text}>
        <ShieldAlert className="size-4 shrink-0" aria-hidden />
        <span>{t('admin.auditChain.notChecked', 'Audit log not checked')}</span>
        <span className="sr-only">{text}</span>
      </ChainLine>
    )
  }
  if (data.breaks.length > 0) {
    return (
      <ChainLine testId="audit-chain-broken" className="text-destructive">
        <ShieldAlert className="size-4 shrink-0" aria-hidden />
        <span>{t('admin.auditChain.brokenTitle', 'Audit log tampered with')}</span>
      </ChainLine>
    )
  }
  const body = t(
    'admin.auditChain.okBody',
    'All {count} entries verify: none was changed or removed since it was written.',
    { count: data.entries }
  )
  return (
    <ChainLine testId="audit-chain-intact" hint={body}>
      <ShieldCheck className="size-4 shrink-0 text-success" aria-hidden />
      <span>{t('admin.auditChain.okTitle', 'Audit log intact')}</span>
      <span className="sr-only">{body}</span>
    </ChainLine>
  )
}

function ChainLine({
  children,
  testId,
  hint,
  busy = false,
  className,
}: {
  children: ReactNode
  testId: string
  hint?: string
  busy?: boolean
  className?: string
}) {
  return (
    <p
      data-testid={testId}
      data-slot="audit-chain-line"
      aria-busy={busy || undefined}
      title={hint}
      className={cn(
        'flex min-h-control items-center gap-1.5 text-sm text-muted-foreground max-md:min-h-control-touch',
        className
      )}
    >
      {children}
    </p>
  )
}

/** The broken chain, in full, above the list; nothing while the log verifies. */
export function AdminAuditChainStatus() {
  const { t } = useTranslation()
  const { data } = useAdminAuditChain()
  if (!data || data.breaks.length === 0) return null
  const reason = (b: AdminAuditChainBreak) =>
    b.reason === 'changed'
      ? t('admin.auditChain.reasonChanged', 'changed after it was written')
      : b.reason === 'gap'
        ? t('admin.auditChain.reasonGap', 'rows are missing before it')
        : t('admin.auditChain.reasonLink', 'does not follow the row before it')

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
