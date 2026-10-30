'use client'

/**
 * A person's initials in a circle: 24px with 12px text (the smallest size
 * that holds the 12px text floor), or 32px. Initials only, no remote image:
 * an avatar URL can point anywhere, and loading it would tell that host who
 * is looking at the page.
 *
 * `UserAvatarStack` lines up to `max` avatars for a compact "who" summary,
 * side by side: overlapping 24px circles would cut the 12px initials. It is
 * decorative (the caller states the count in text).
 */

import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { initials } from '@/lib/initials'
import { cn } from '@/lib/utils'

export interface UserAvatarProps {
  name: string
  size?: 'sm' | 'md'
  className?: string
}

export function UserAvatar({ name, size = 'sm', className }: UserAvatarProps) {
  return (
    <Avatar className={cn(size === 'sm' ? 'size-6' : 'size-8', className)} aria-hidden>
      <AvatarFallback className="text-xs font-medium text-foreground">
        {initials(name)}
      </AvatarFallback>
    </Avatar>
  )
}

export interface UserAvatarStackProps {
  names: string[]
  max?: number
  className?: string
}

export function UserAvatarStack({ names, max = 3, className }: UserAvatarStackProps) {
  if (names.length === 0) return null
  return (
    <span className={cn('flex shrink-0 gap-1', className)} aria-hidden>
      {names.slice(0, max).map((name, i) => (
        <UserAvatar key={`${name}-${i}`} name={name} />
      ))}
    </span>
  )
}
