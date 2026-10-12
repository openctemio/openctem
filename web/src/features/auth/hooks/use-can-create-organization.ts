'use client'

import { useBootstrapContextOptional } from '@/context/bootstrap-provider'
import { useAuthProviders } from '../api/use-auth-providers'
import { canCreateOrganization } from '../lib/organization-creation'

export interface CanCreateOrganization {
  /** The user may create an organization (server policy `self_service`). */
  canCreate: boolean
  /** The policy is still loading; `canCreate` is false until it arrives. */
  isLoading: boolean
}

/** A rate-limited answer says nothing about the policy; it is retried. */
function isRateLimited(error: unknown): boolean {
  return (error as { statusCode?: number } | undefined)?.statusCode === 429
}

/**
 * Whether this installation lets users create organizations. Every
 * "Create organization" affordance goes through this, so
 * `TENANT_CREATION_MODE=admin_only` hides them all.
 *
 * While loading, nothing is offered. A 429 counts as still loading (the
 * public endpoint shares the auth rate limit with sign-in, and offering
 * creation on a 429 showed "Create organization" under `admin_only`). If the
 * policy cannot be fetched otherwise, creation is offered (the server
 * default) and the server still refuses it under `admin_only`.
 */
export function useCanCreateOrganization(): CanCreateOrganization {
  // Inside the app shell the session bootstrap reports the policy, so the
  // public /auth/providers (which shares the sign-in rate limit) is only
  // asked on the auth pages, or when the bootstrap did not carry it.
  const bootstrap = useBootstrapContextOptional()
  const fromBootstrap = bootstrap?.data?.tenant_creation_mode
  const waitForBootstrap = bootstrap !== null && bootstrap.isLoading
  const skipProviders = waitForBootstrap || fromBootstrap !== undefined
  const { data, error, isLoading } = useAuthProviders(undefined, !skipProviders)

  if (fromBootstrap !== undefined) {
    return { canCreate: canCreateOrganization(fromBootstrap), isLoading: false }
  }
  if (waitForBootstrap) return { canCreate: false, isLoading: true }
  const loading = !data && ((isLoading && !error) || isRateLimited(error))
  return {
    canCreate: !loading && canCreateOrganization(data?.tenant_creation_mode),
    isLoading: loading,
  }
}
