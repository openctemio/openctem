/**
 * What the /welcome hub offers, from the API's onboarding options. Pure, so
 * the states are tested without rendering: the API decides, the web never
 * adds an offer of its own.
 */

import type { OnboardingOptions } from '@/features/auth/actions/local-auth-actions'

export interface WelcomeView {
  /** The address is not verified: nothing is listed until it is. */
  verifyFirst: boolean
  invitations: OnboardingOptions['invitations']
  organizations: OnboardingOptions['organizations']
  /**
   * "Create an organization" is offered only when the API's policy says this
   * person may. A missing or false answer hides it (fail closed).
   */
  canCreate: boolean
  /**
   * Nothing to join and nothing to create: the person asks an administrator
   * to invite them. This is the whole hub on a self-hosted installation where
   * only the platform administrator creates organizations.
   */
  askAdministrator: boolean
}

export function welcomeView(options: OnboardingOptions | null): WelcomeView {
  const invitations = options?.invitations ?? []
  const organizations = options?.organizations ?? []
  const canCreate = options?.can_create_organization === true
  return {
    verifyFirst: !!options && !options.email_verified,
    invitations,
    organizations,
    canCreate,
    askAdministrator: !canCreate,
  }
}
