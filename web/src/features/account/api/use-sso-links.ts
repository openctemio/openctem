/**
 * Organization sign-in of the signed-in account (Account > Security): the
 * member's organizations with single sign-on and the account's identity at
 * each. Linking and unlinking carry the proof typed in the confirm dialog.
 * The link start runs as a server action (the browser binding stays in an
 * HttpOnly cookie) and the browser goes to the organization's identity
 * provider; the SSO link route finishes it and comes back here.
 */

import useSWR from 'swr'
import { useCallback, useState } from 'react'

import { del, get } from '@/lib/api/client'
import { userEndpoints } from '@/lib/api/endpoints'
import type { LinkProof, LinkProofKind } from '@/features/auth/actions/social-auth-actions'
import { startSSOLinkAction } from '@/features/sso/actions/sso-link-actions'
import type { SSOProviderType } from '@/features/sso/types/sso.types'

export interface SSOLinkedIdentity {
  id: string
  created_at: string
  last_used_at?: string
  /** The person may remove it here (the account has a password). */
  unlinkable: boolean
}

export interface SSOLinkOrganization {
  org_slug: string
  org_name: string
  provider: SSOProviderType
  display_name: string
  /** Absent when the organization's sign-in is not linked. */
  identity?: SSOLinkedIdentity
}

export interface SSOLinks {
  organizations: SSOLinkOrganization[]
  /** Organization identities not matched to an organization listed above. */
  other: SSOLinkedIdentity[]
  proof: LinkProofKind
}

export function useSSOLinks() {
  const { data, error, isLoading, mutate } = useSWR<SSOLinks>(
    userEndpoints.ssoLinks(),
    (url: string) => get<SSOLinks>(url),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  return { links: data, isLoading, isError: !!error, mutate }
}

/** A refused link start, shaped like an API error so the dialog shows its message. */
class SSOLinkStartRefused extends Error {
  constructor(
    readonly code?: string,
    readonly statusCode?: number
  ) {
    super('')
    this.name = 'SSOLinkStartRefused'
  }
}

/** Starts linking an organization's sign-in; resolves only on failure (the page navigates away). */
export function useStartSSOLink() {
  const [linking, setLinking] = useState<string | null>(null)
  const link = useCallback(async (org: SSOLinkOrganization, proof: LinkProof) => {
    const key = `${org.org_slug}/${org.provider}`
    setLinking(key)
    try {
      const res = await startSSOLinkAction(org.org_slug, org.provider, proof)
      if (!res.success) throw new SSOLinkStartRefused(res.code, res.status)
      window.location.assign(res.authorizationUrl)
    } catch (err) {
      setLinking(null)
      throw err
    }
  }, [])
  return { link, linking }
}

export function useUnlinkSSOIdentity() {
  const [isUnlinking, setIsUnlinking] = useState(false)
  const unlink = useCallback(async (id: string, proof: LinkProof) => {
    setIsUnlinking(true)
    try {
      await del(userEndpoints.ssoLink(id), { step_up: proof })
    } finally {
      setIsUnlinking(false)
    }
  }, [])
  return { unlink, isUnlinking }
}
