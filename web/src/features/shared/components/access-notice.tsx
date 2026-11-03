'use client'

import type { ReactNode } from 'react'
import { Lock, PackageX } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { describePermissionDenied } from '@/lib/api/permission-denied'

export type AccessNoticeKind = 'no_access' | 'module_off' | 'module_unavailable'

export interface AccessNoticeProps {
  /** Why the content is not shown. */
  kind: AccessNoticeKind
  /** What is not shown, e.g. "Members" or "program metrics": "You do not have access to {title}". */
  title: string
  /**
   * The refusal's details (api permission_denied.go: missing_permissions,
   * any_of, required_role). The notice names the permission, the built-in
   * roles that hold it, and who can grant it.
   */
  details?: unknown
  /** The sentence under the title, when the caller knows better (e.g. "you can turn it on"). */
  hint?: string
  /** Buttons under the text (Go back, Manage modules). */
  actions?: ReactNode
  className?: string
}

/**
 * The one way the console says "you cannot see this": a refused read inside a
 * page (ErrorState, NoAccessState) and a refused page (RouteGuard) look and
 * read the same. It names what is missing and who can give it, never offers a
 * Retry that cannot help, and never shows the API's raw message.
 *
 * Display only: hiding content is a convenience, the API decides every request.
 */
export function AccessNotice({
  kind,
  title,
  details,
  hint,
  actions,
  className,
}: AccessNoticeProps) {
  const { t } = useTranslation()
  const heading =
    kind === 'no_access'
      ? t('common.noAccessTo', 'You do not have access to {title}', { title })
      : kind === 'module_off'
        ? t('common.moduleOffFor', '{title} is not enabled for this organization', { title })
        : t('limits.access.unavailableTitle', 'Not available for this organization')
  const body =
    hint ??
    (kind === 'no_access'
      ? (describePermissionDenied(details, t) ??
        t('common.noAccessHint', 'Ask an organization administrator to grant access.'))
      : kind === 'module_off'
        ? t('common.moduleOffHint', 'Ask an organization administrator to enable it.')
        : t(
            'limits.access.unavailableHelp',
            'Contact the administrator of this installation to make it available.'
          ))
  const Icon = kind === 'no_access' ? Lock : PackageX
  return (
    <Alert className={className} data-slot="access-notice" data-kind={kind}>
      <Icon aria-hidden />
      <AlertTitle>{heading}</AlertTitle>
      <AlertDescription>
        <p>{body}</p>
        {actions && <div className="mt-3 flex flex-wrap gap-2">{actions}</div>}
      </AlertDescription>
    </Alert>
  )
}
