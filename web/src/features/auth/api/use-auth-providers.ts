/**
 * Auth Providers API Hook
 *
 * Fetches which social OAuth providers the backend actually has configured,
 * so the login page only renders buttons that will work (no dead affordances).
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useBootstrapContextOptional } from '@/context/bootstrap-provider'
import { get } from '@/lib/api/client'

import type { PasswordPolicy } from '../lib/password-policy'

// ============================================
// TYPES
// ============================================

export interface AuthProvidersResponse {
  /** Which social OAuth providers are configured on the backend */
  social: {
    microsoft: boolean
    google: boolean
    github: boolean
  }
  /** Whether the global SSO_ENTRA_* env fallback is enabled */
  sso_env_entra_enabled: boolean
  /**
   * Whether people may create their own account at /register. Off by default:
   * administrators create accounts. An invitation link still allows sign-up for
   * the invited email. Treat a missing value as false.
   */
  registration_enabled?: boolean
  /** Who may create organizations (server policy). */
  tenant_creation_mode?: string
  /** Whether people who cannot sign up may request an organization. */
  request_access?: boolean
  /** The password rules the server enforces and the reset-link lifetime. */
  password_policy?: PasswordPolicy
  /** Turnstile site key; set when the sign-up forms must pass a CAPTCHA. */
  captcha_site_key?: string
  /** DEPLOYMENT_REGION: the region a new organization gets (fixed). */
  deployment_region?: string
  /**
   * Whether this server can send email. False: forgot-password, verification
   * and invitation emails are not sent, so forms say "ask your administrator"
   * and administrators copy links by hand. Absent until loaded: treat only an
   * explicit false as "no email".
   */
  email_delivery?: boolean
}

// ============================================
// CONFIG
// ============================================

const URL = '/api/v1/auth/providers'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  // Public endpoint; don't hammer it on 4xx. 429 (rate limited) is transient:
  // retry it, or the policy it carries stays unknown for the session.
  shouldRetryOnError: (error: { statusCode?: number }) => {
    if (error?.statusCode === 429) return true
    if (error?.statusCode && error.statusCode >= 400 && error.statusCode < 500) return false
    return true
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 60_000,
}

// ============================================
// HOOK
// ============================================

/**
 * Fetch configured auth providers (public, no auth required).
 * Consumers should render social buttons only for providers reported `true`.
 */
export function useAuthProviders(config?: SWRConfiguration, enabled = true) {
  return useSWR<AuthProvidersResponse>(
    enabled ? URL : null,
    (url: string) => get<AuthProvidersResponse>(url),
    {
      ...defaultConfig,
      ...config,
    }
  )
}

/**
 * The password policy the server enforces (undefined until it is loaded).
 * Forms state and pre-check it from here, never from their own constants.
 */
export function usePasswordPolicy(): PasswordPolicy | undefined {
  return useAuthProviders().data?.password_policy
}

/**
 * True when the server reports it cannot send email (false until the answer
 * is loaded, so forms do not flash the no-email variant).
 *
 * Inside the app shell the session bootstrap carries the flag, so a dashboard
 * page (the members page) never asks the public /auth/providers for it; the
 * auth pages, or an API whose bootstrap lacks the field, ask that endpoint.
 */
export function useEmailUnavailable(): boolean {
  const bootstrap = useBootstrapContextOptional()
  const fromBootstrap = bootstrap?.data?.email_delivery
  const waitForBootstrap = bootstrap !== null && bootstrap.isLoading
  const skipProviders = waitForBootstrap || fromBootstrap !== undefined
  const { data } = useAuthProviders(undefined, !skipProviders)
  if (fromBootstrap !== undefined) return fromBootstrap === false
  return data?.email_delivery === false
}
