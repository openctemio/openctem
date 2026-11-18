'use client'

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * The e-mail address to show under a person's name, or nothing when it would
 * repeat the title: no name, or a name that is the address itself (accounts
 * created by invitation or SSO often carry the address as their name).
 */
export function distinctAddress(name: string | undefined, email: string): string | undefined {
  const n = name?.trim()
  if (!n || n.toLowerCase() === email.trim().toLowerCase()) return undefined
  return email
}

/**
 * A person on a phone (members, invitations):
 *
 *   Example Person ........................................ (...)
 *   person@example.com
 *   Administrator   Active   Two-factor on
 *
 * The title (the name, or the address when there is no name) has the card's
 * width minus the menu's own column, so the menu never covers text; the
 * address is shown once; a long address breaks inside the card. Facts
 * (role, status, badges) share one line and wrap only when they do not fit.
 */
export function PersonPhoneCard({
  title,
  address,
  facts,
  menu,
  onOpen,
  dimmed = false,
}: {
  title: ReactNode
  address?: ReactNode
  facts?: ReactNode
  menu?: ReactNode
  /** A tap on the card (outside its buttons and links). */
  onOpen?: () => void
  /** A deactivated member: the text is faded. */
  dimmed?: boolean
}) {
  return (
    <div
      data-slot="mobile-card"
      className={cn(
        'flex items-start gap-2 px-3 py-3',
        onOpen && 'cursor-pointer hover:bg-muted/50'
      )}
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href], [role="menuitem"]')) return
        onOpen?.()
      }}
    >
      <div className={cn('min-w-0 flex-1 space-y-1', dimmed && 'opacity-60')}>
        <div
          data-slot="person-card-title"
          className="text-body font-medium [overflow-wrap:anywhere]"
        >
          {title}
        </div>
        {address && (
          <div
            data-slot="person-card-address"
            className="text-cap text-muted-foreground [overflow-wrap:anywhere]"
          >
            {address}
          </div>
        )}
        {facts && (
          <div
            data-slot="person-card-facts"
            className="flex flex-wrap items-center gap-x-3 gap-y-1"
          >
            {facts}
          </div>
        )}
      </div>
      {menu && <div className="shrink-0">{menu}</div>}
    </div>
  )
}
