'use client'

import { AuthenticationSettings } from './authentication-settings'
import { GeneralSettings } from './general-settings'

export type OrganizationSettingsView = 'general' | 'authentication'

/**
 * The two pages over the organization's settings load:
 * - /settings/general: name, URL, logo, website, file storage and the owner's
 *   danger zone (general-settings.tsx);
 * - /settings/authentication: two-factor, new members, allowed domains, the
 *   IP allowlist, invitations and personal accounts (authentication-settings.tsx).
 * What scan jobs may do on sensors (the rest of the security section) is
 * Scanning › Sensor job safety (features/sensors/components/sensor-job-safety-settings.tsx).
 */
export function OrganizationSettings({ view }: { view: OrganizationSettingsView }) {
  return view === 'authentication' ? <AuthenticationSettings /> : <GeneralSettings />
}
