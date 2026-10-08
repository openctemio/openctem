'use client'

import useSWR from 'swr'
import type { SignupPolicyResponse, UpdateSignupPolicyRequest } from '@/lib/api/generated'
import { adminFetch, adminFetcher } from './admin-client'

const KEY = '/settings/signup'

/** Who may create an organization (System > Sign-up). Any administrator reads it. */
export function useSignupPolicy() {
  return useSWR<SignupPolicyResponse>(KEY, adminFetcher)
}

/**
 * Changes the policy (super admin). `version` is the version that was read
 * (409 when someone else saved since); `totp_code` is a fresh code from the
 * console authenticator.
 */
export function saveSignupPolicy(input: UpdateSignupPolicyRequest) {
  return adminFetch<SignupPolicyResponse>(KEY, { method: 'PUT', body: input })
}
