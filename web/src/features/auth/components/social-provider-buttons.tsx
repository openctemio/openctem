'use client'

import type { ReactNode } from 'react'
import { Loader2 } from 'lucide-react'

import { IconGoogle, IconGithub, IconMicrosoft } from '@/assets/brand-icons'
import { EntryDivider } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import type { SocialProvider } from '../actions/social-auth-actions'
import type { AuthProvidersResponse } from '../api/use-auth-providers'

const SOCIAL_PROVIDERS: {
  id: SocialProvider
  name: string
  icon: React.ComponentType<{ className?: string }>
}[] = [
  { id: 'google', name: 'Google', icon: IconGoogle },
  { id: 'github', name: 'GitHub', icon: IconGithub },
  { id: 'microsoft', name: 'Microsoft', icon: IconMicrosoft },
]

const GRID = 'grid grid-cols-[repeat(auto-fit,minmax(7rem,1fr))] gap-2'

/**
 * The social sign-in buttons of the sign-in and sign-up cards, with their
 * divider. Only providers the API reports configured are shown (no button that
 * dead-ends). While that answer loads, the block holds its place with a
 * skeleton of the same divider and grid, so the card does not grow and push
 * its footer down when the buttons arrive. A failed answer or no configured
 * provider shows nothing.
 */
export function SocialProviderButtons({
  providers,
  failed,
  divider,
  disabled,
  loadingProvider,
  onSelect,
}: {
  /** The `/auth/providers` answer; undefined while it loads. */
  providers: AuthProvidersResponse | undefined
  /** The answer could not be loaded. */
  failed: boolean
  divider: ReactNode
  disabled: boolean
  loadingProvider: SocialProvider | null
  onSelect: (provider: SocialProvider) => void
}) {
  const loading = providers === undefined && !failed
  const enabled = providers
    ? SOCIAL_PROVIDERS.filter((provider) => providers.social?.[provider.id])
    : []
  if (!loading && enabled.length === 0) return null

  const line = <EntryDivider>{divider}</EntryDivider>
  const grid = loading ? (
    <div className={GRID} data-slot="social-providers-pending" aria-hidden>
      {SOCIAL_PROVIDERS.map((provider) => (
        <Skeleton key={provider.id} className="h-9" />
      ))}
    </div>
  ) : (
    <div className={GRID}>
      {enabled.map((provider) => (
        <Button
          key={provider.id}
          variant="outline"
          type="button"
          disabled={disabled}
          onClick={() => onSelect(provider.id)}
        >
          {loadingProvider === provider.id ? (
            <Loader2 aria-hidden className="size-4 animate-spin" />
          ) : (
            <provider.icon className="size-4" />
          )}
          <span>{provider.name}</span>
        </Button>
      ))}
    </div>
  )
  return (
    <>
      {line}
      {grid}
    </>
  )
}
