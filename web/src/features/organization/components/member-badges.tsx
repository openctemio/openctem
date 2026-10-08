import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

import { memberBadges, type MemberBadgeTone } from '../lib/external-access'
import type { MemberWithUser } from '../types/member.types'

const TONE_CLASS: Record<MemberBadgeTone, string> = {
  neutral: '',
  info: 'border-info/40 text-info',
  warning: 'border-warning/40 text-warning',
  danger: 'border-destructive/40 text-destructive',
}

/**
 * Where a member comes from and how their access is bounded (api RFC-058):
 * External / Personal / Unmanaged, Lapsed domain, SSO exception, end of
 * access. Renders nothing for an ordinary internal member.
 */
export function MemberBadges({
  member,
  ssoExceptionUntil,
  className,
}: {
  member: Pick<
    MemberWithUser,
    'kind' | 'home_organization' | 'personal' | 'domain_lapsed' | 'access_expires_at' | 'status'
  >
  ssoExceptionUntil?: string
  className?: string
}) {
  const badges = memberBadges(member, { ssoExceptionUntil })
  if (badges.length === 0) return null
  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1', className)}>
      {badges.map((b) => (
        <Badge
          key={b.key}
          variant="outline"
          className={cn('h-5 px-1.5 text-[11px] font-normal', TONE_CLASS[b.tone])}
          title={b.title}
          data-testid={`member-badge-${b.key}`}
        >
          {b.label}
          <span className="sr-only">: {b.title}</span>
        </Badge>
      ))}
    </span>
  )
}
