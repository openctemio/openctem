/**
 * Linked sign-in methods of the signed-in account (Account > Security).
 *
 * Linking and unlinking carry the proof typed in the confirm dialog (the
 * authenticator code, else the password; a recent sign-in does not count).
 * Linking then goes through the provider: the API returns the authorization URL, the state and
 * the one-time browser binding are kept in httpOnly cookies by a server action, and the browser goes to the
 * provider. The OAuth callback route finishes the link and comes back to
 * Account > Security with the result.
 */

import useSWR from 'swr'
import { useCallback, useState } from 'react'

import { del, get, post } from '@/lib/api/client'
import { userEndpoints } from '@/lib/api/endpoints'
import {
  rememberLinkState,
  type LinkProof,
  type LinkProofKind,
} from '@/features/auth/actions/social-auth-actions'

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
  /** What linking or unlinking asks for; '' when the account must turn on 2FA first. */
  proof: LinkProofKind
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
  const link = useCallback(async (provider: LinkProvider, proof: LinkProof) => {
    setLinking(provider)
    try {
      const res = await post<{ authorization_url: string; state: string; browser_binding: string }>(
        userEndpoints.identityLink(provider),
        { redirect_uri: `${window.location.origin}/auth/callback/${provider}`, step_up: proof }
      )
      const kept = await rememberLinkState(provider, res.state, res.browser_binding)
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
  const unlink = useCallback(async (id: string, proof: LinkProof) => {
    setIsUnlinking(true)
    try {
      await del(userEndpoints.identity(id), { step_up: proof })
    } finally {
      setIsUnlinking(false)
    }
  }, [])
  return { unlink, isUnlinking }
}
