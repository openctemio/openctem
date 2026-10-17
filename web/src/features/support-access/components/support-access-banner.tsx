'use client'

/**
 * Tells every member, under the header, while platform support can read the
 * organization's data (api RFC-063): who, which data, until when, and whether
 * a support session is open right now. Not dismissible: it is the members'
 * view of an access the owners granted. Owners and admins get a link to the
 * Support access page to revoke it. One small read on load, on focus and
 * once a minute.
 */

import { Eye, LifeBuoy } from 'lucide-react'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import { useActiveSupportAccess } from '../api/use-support-access'
import { formatSupportScopes, formatSupportTime } from '../lib/format'

export const SUPPORT_ACCESS_SETTINGS_HREF = '/settings/support-access'

export function SupportAccessBanner() {
  const { t, locale } = useTranslation()
  const bootstrapPending = useBootstrapPending()
  const active = useActiveSupportAccess(!bootstrapPending)
  const { isAtLeast } = usePermissions()
  if (active.length === 0) return null
  const canManage = isAtLeast('admin')

  return (
    <div
      className="space-y-2 px-4 pt-2"
      role="region"
      aria-label={t('supportAccess.banner.region', 'Platform support access')}
    >
      {active.map((g, i) => {
        const vars = {
          name: g.admin_name || t('supportAccess.banner.someone', 'an administrator'),
          scopes: formatSupportScopes(g.scopes, t),
          time: formatSupportTime(g.expires_at, locale),
        }
        const Icon = g.open_session ? Eye : LifeBuoy
        return (
          <div
            key={`${g.admin_name}-${g.expires_at}-${i}`}
            role={g.open_session ? 'alert' : 'status'}
            data-testid="support-access-banner"
            data-viewing={g.open_session ? 'true' : 'false'}
            className={cn(
              'flex flex-col gap-2 rounded-md border px-3 py-2 text-sm sm:flex-row sm:items-start',
              g.open_session
                ? 'border-destructive/50 bg-destructive/10 font-medium'
                : 'border-warning/40 bg-warning/10'
            )}
          >
            <div className="flex min-w-0 flex-1 items-start gap-3">
              <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              <p className="min-w-0 flex-1 break-words">
                {g.open_session
                  ? t(
                      'supportAccess.banner.viewing',
                      'Platform support ({name}) is viewing your {scopes} now, read-only, until {time}.',
                      vars
                    )
                  : t(
                      'supportAccess.banner.granted',
                      'Platform support ({name}) can view your {scopes}, read-only, until {time}.',
                      vars
                    )}
                {g.case_ref
                  ? ` ${t('supportAccess.banner.case', '(case {ref})', { ref: g.case_ref })}`
                  : ''}
              </p>
            </div>
            {canManage && (
              <Link
                href={SUPPORT_ACCESS_SETTINGS_HREF}
                className="shrink-0 ps-7 text-sm font-medium underline underline-offset-2 sm:ps-0"
              >
                {t('supportAccess.banner.manage', 'Manage support access')}
              </Link>
            )}
          </div>
        )
      })}
    </div>
  )
}
