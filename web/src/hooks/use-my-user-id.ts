'use client'

import { useProfile } from '@/features/account/api/use-profile'

/**
 * The signed-in person's user id, for "is this mine" decisions: "You" on your
 * own request, Remind and Withdraw on it, the "Mine" filter, an owner's rights,
 * a per-person draft key.
 *
 * It comes from the profile (`/users/me`, seeded by the session bootstrap), and
 * is `undefined` until the profile has loaded. It never comes from the auth
 * store: the session token is an httpOnly cookie the page cannot read, so the
 * store's user is empty on most page loads, and every own row would look like
 * someone else's. A source test keeps the store's id out of these decisions.
 */
export function useMyUserId(): string | undefined {
  return useProfile().profile?.id || undefined
}
