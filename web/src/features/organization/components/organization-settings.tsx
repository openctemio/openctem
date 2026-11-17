'use client'

import { GeneralSettings } from './general-settings'

export type OrganizationSettingsView = 'general'

/**
 * /settings/general: name, URL, logo, website, file storage and the owner's
 * danger zone (general-settings.tsx). How people sign in and who may join is
 * Settings › Sign-in (sign-in-settings.tsx); what scan jobs may do on sensors
 * is Scanning › Sensor job safety
 * (features/sensors/components/sensor-job-safety-settings.tsx).
 */
export function OrganizationSettings(_props: { view: OrganizationSettingsView }) {
  return <GeneralSettings />
}
