/**
 * Linked sign-in methods of the signed-in account (Account > Security).
 *
 * Linking and unlinking carry the proof typed in the confirm dialog (the
 * authenticator code, else the password; a recent sign-in does not count).
 * Linking then goes through the provider: a server action starts the link with the API and keeps the
 * state and the one-time browser binding in httpOnly cookies (the binding never reaches page
 * JavaScript), and the browser goes to the provider. The OAuth callback route finishes the link and comes back to
 * Account > Security with the result.
 */

import useSWR from 'swr'
import { useCallback, useState } from 'react'

import { del, get } from '@/lib/api/client'
import { userEndpoints } from '@/lib/api/endpoints'
import {
  startLinkAction,
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

/** A refused link start, shaped like an API error so the dialog shows its message. */
class LinkStartRefused extends Error {
  constructor(
    readonly code?: string,
    readonly statusCode?: number
  ) {
    super('')
    this.name = 'LinkStartRefused'
  }
}

/** Starts linking a provider; resolves only on failure (the page navigates away). */
export function useLinkProvider() {
  const [linking, setLinking] = useState<LinkProvider | null>(null)
  const link = useCallback(async (provider: LinkProvider, proof: LinkProof) => {
    setLinking(provider)
    try {
      // The start runs on the server: the browser binding stays out of this page.
      const res = await startLinkAction(provider, proof)
      if (!res.success) throw new LinkStartRefused(res.code, res.status)
      window.location.assign(res.authorizationUrl)
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
