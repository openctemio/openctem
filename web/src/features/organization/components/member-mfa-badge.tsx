'use client'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'

import type { MemberMfaStatus } from '../types/member.types'

/**
 * Two-factor status of a member, as shown to owners and admins. In the table
 * the column header says "Two-factor"; a phone card has no header, so it
 * passes `labelled` and the badge says "Two-factor on" / "Two-factor off".
 */
export function MemberMfaBadge({
  status,
  labelled = false,
}: {
  status?: MemberMfaStatus
  labelled?: boolean
}) {
  const { t } = useTranslation()
  switch (status) {
    case 'enabled':
      return (
        <Badge variant="outline" className="border-success/40 text-success">
          {labelled
            ? t('org.membersPage.mfa.onLabelled', 'Two-factor on')
            : t('org.membersPage.mfa.on', 'On')}
        </Badge>
      )
    case 'disabled':
      return (
        <Badge variant="outline">
          {labelled
            ? t('org.membersPage.mfa.offLabelled', 'Two-factor off')
            : t('org.membersPage.mfa.off', 'Off')}
        </Badge>
      )
    case 'idp':
      return (
        <span
          className="text-sm text-muted-foreground"
          title={t('org.membersPage.mfa.idpHint', 'Handled by the identity provider')}
        >
          {labelled
            ? t('org.membersPage.mfa.idpLabelled', 'Two-factor via SSO')
            : t('org.membersPage.mfa.idp', 'Via SSO')}
        </span>
      )
    default:
      return <span className="text-sm text-muted-foreground">—</span>
  }
}
