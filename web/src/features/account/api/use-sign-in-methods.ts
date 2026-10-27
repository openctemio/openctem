/**
 * Linked sign-in methods of the signed-in account (Account > Security).
 *
 * Linking goes through the provider: the API returns the authorization URL
 * (after a fresh step-up, which the shared API client asks for), the state is
 * kept in an httpOnly cookie by a server action, and the browser goes to the
 * provider. The OAuth callback route finishes the link and comes back to
 * Account > Security with the result.
 */

import useSWR from 'swr'
import { useCallback, useState } from 'react'

import { del, get, post } from '@/lib/api/client'
import { userEndpoints } from '@/lib/api/endpoints'
import { rememberLinkState } from '@/features/auth/actions/social-auth-actions'

import type { LinkProvider } from '../lib/link-result'

export interface SignInMethod {
  id: string
  /** google, github, microsoft, or organization (an organization's SSO). */
  provider: LinkProvider | 'organization'
  created_at: string
  last_used_at?: string
  /** The person may remove it now: not the account's last sign-in method. */
  unlinkable: boolean
}

export interface SignInMethods {
  password: boolean
  identities: SignInMethod[]
  /** Providers this platform offers for linking. */
  available: string[]
}

export function useSignInMethods() {
  const { data, error, isLoading, mutate } = useSWR<SignInMethods>(
    userEndpoints.identities(),
    (url: string) => get<SignInMethods>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  return { methods: data, isLoading, isError: !!error, mutate }
}

/** Starts linking a provider; resolves only on failure (the page navigates away). */
export function useLinkProvider() {
  const [linking, setLinking] = useState<LinkProvider | null>(null)
  const link = useCallback(async (provider: LinkProvider) => {
    setLinking(provider)
    try {
      const res = await post<{ authorization_url: string; state: string }>(
        userEndpoints.identityLink(provider),
        { redirect_uri: `${window.location.origin}/auth/callback/${provider}` }
      )
      const kept = await rememberLinkState(provider, res.state)
      if (!kept.success) throw new Error('link state not kept')
      window.location.assign(res.authorization_url)
    } catch (err) {
      setLinking(null)
      throw err
    }
  }, [])
  return { link, linking }
}

export function useUnlinkIdentity() {
  const [isUnlinking, setIsUnlinking] = useState(false)
  const unlink = useCallback(async (id: string) => {
    setIsUnlinking(true)
    try {
      await del(userEndpoints.identity(id))
    } finally {
      setIsUnlinking(false)
    }
  }, [])
  return { unlink, isUnlinking }
}
