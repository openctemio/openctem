'use client'

import { CalendarClock, Globe, ShieldCheck, Users } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { RoleRiskBadge, RoleSummaryLine } from '@/features/access-control/components/role-risk'
import type { RoleSummary } from '@/features/access-control/types/role.types'

/** What an invitation gives, as the public lookup returns it (api RFC-095 §5). */
export interface InvitationGrants {
  roles?: { id: string; name: string; slug: string; is_system: boolean; summary?: RoleSummary }[]
  teams?: { id: string; name: string }[]
  member_kind?: 'internal' | 'external' | string
  access_expires_at?: string
  mfa_required?: boolean
  mfa_reason?: 'outside_privileged' | 'organization_policy' | string
}

function formatDay(iso: string, locale: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(locale, { year: 'numeric', month: 'short', day: 'numeric' })
}

/**
 * The acceptance page's notices: the roles with their risk, the teams (or
 * that none are set yet), whether the person joins from outside the
 * organization, when access ends and whether two-factor authentication will
 * be required. Shown before the person accepts or declines.
 */
export function InvitationGrantsNotice({
  grants,
  organization,
}: {
  grants: InvitationGrants
  organization: string
}) {
  const { t, locale } = useTranslation()
  const roles = grants.roles ?? []
  const teams = grants.teams ?? []
  const fullData = roles.some(
    (r) => r.summary?.reasons.includes('full_data') || r.summary?.reasons.includes('admin')
  )

  return (
    <section aria-labelledby="invitation-grants-title" className="space-y-4">
      <h2 id="invitation-grants-title" className="text-sm font-semibold">
        {t('org.acceptInvite.whatYouGet')}
      </h2>

      {roles.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {roles.length === 1 ? t('org.acceptInvite.role') : t('org.acceptInvite.roles')}
          </p>
          <ul className="space-y-2">
            {roles.map((r) => (
              <li key={r.id} className="rounded-md border px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{r.name}</span>
                  {r.summary && <RoleRiskBadge risk={r.summary.risk} />}
                </div>
                {r.summary && <RoleSummaryLine summary={r.summary} className="mt-1" />}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="space-y-1">
        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          <Users className="h-3.5 w-3.5" aria-hidden />
          {t('org.acceptInvite.teams')}
        </p>
        {teams.length > 0 ? (
          <ul className="flex flex-wrap gap-1.5">
            {teams.map((tm) => (
              <li key={tm.id} className="rounded-full border bg-muted/40 px-2.5 py-0.5 text-sm">
                {tm.name}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            {fullData ? t('org.acceptInvite.noTeamsFullData') : t('org.acceptInvite.noTeams')}
          </p>
        )}
      </div>

      <ul className="space-y-2 text-sm">
        {grants.member_kind === 'external' && (
          <li className="flex gap-2">
            <Globe className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
            <span>{t('org.acceptInvite.outside', undefined, { org: organization })}</span>
          </li>
        )}
        <li className="flex gap-2">
          <CalendarClock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          <span>
            {grants.access_expires_at
              ? t('org.acceptInvite.accessEnds', undefined, {
                  date: formatDay(grants.access_expires_at, locale),
                })
              : t('org.acceptInvite.noAccessEnd')}
          </span>
        </li>
        {grants.mfa_required && (
          <li className="flex gap-2">
            <ShieldCheck
              className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400"
              aria-hidden
            />
            <span>
              {grants.mfa_reason === 'outside_privileged'
                ? t('org.acceptInvite.mfaOutside', undefined, { org: organization })
                : t('org.acceptInvite.mfaPolicy', undefined, { org: organization })}
            </span>
          </li>
        )}
      </ul>
    </section>
  )
}
