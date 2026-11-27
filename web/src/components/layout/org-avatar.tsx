import { cn } from '@/lib/utils'
import { orgInitials } from './org-initials'

/**
 * An organization's initials on a neutral tile, so each organization is
 * recognisable wherever it is listed: the organization card and switcher, an
 * invitation, an ownership invitation. Decorative: the name always stands
 * beside it.
 */
export function OrgAvatar({ name, size = 'md' }: { name: string; size?: 'sm' | 'md' }) {
  return (
    <span
      aria-hidden
      data-slot="org-avatar"
      className={cn(
        'flex shrink-0 items-center justify-center rounded-md bg-muted font-semibold text-foreground ring-1 ring-border',
        size === 'md' ? 'size-9 text-cap' : 'size-6 text-cap'
      )}
    >
      {orgInitials(name)}
    </span>
  )
}
