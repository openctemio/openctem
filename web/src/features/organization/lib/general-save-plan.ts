/**
 * What the Organization › General "Save changes" button writes.
 *
 * One Save covers the whole tab: the organization profile (name, slug), the
 * general settings section and the logo. The logo used to have its own small
 * Save next to the avatar, so the header Save answered "No changes to save"
 * while a new logo was pending, and leaving the page dropped it (23a B14).
 *
 * `logoDraft`: `undefined` = unchanged, a data URL = replace, `null` = remove.
 */

export interface GeneralSettingsValues {
  timezone: string
  language: string
  industry: string
  website: string
}

export interface BrandingValues {
  primary_color: string
  logo_dark_url: string
  logo_data: string | null
}

export interface GeneralSavePlanInput {
  orgInfo: { name: string; slug: string }
  current: { name?: string; slug?: string } | null | undefined
  generalForm: GeneralSettingsValues
  savedGeneral: Partial<GeneralSettingsValues> | null | undefined
  branding: BrandingValues
  logoDraft: string | null | undefined
}

export interface GeneralSavePlan {
  orgChanges: { name?: string; slug?: string } | null
  general: GeneralSettingsValues | null
  /** Full branding struct (PATCH /settings/branding replaces it whole). */
  branding: BrandingValues | null
}

export function planGeneralSave(input: GeneralSavePlanInput): GeneralSavePlan {
  const { orgInfo, current, generalForm, savedGeneral, branding, logoDraft } = input

  const orgChanges: { name?: string; slug?: string } = {}
  if (orgInfo.name !== current?.name) orgChanges.name = orgInfo.name
  if (orgInfo.slug !== current?.slug) orgChanges.slug = orgInfo.slug

  const generalChanged =
    !!savedGeneral &&
    (generalForm.timezone !== (savedGeneral.timezone || 'UTC') ||
      generalForm.language !== (savedGeneral.language || 'en') ||
      generalForm.industry !== (savedGeneral.industry || '') ||
      generalForm.website !== (savedGeneral.website || ''))

  return {
    orgChanges: Object.keys(orgChanges).length > 0 ? orgChanges : null,
    general: generalChanged ? generalForm : null,
    // Echo primary_color/logo_dark_url back: omitted fields would reset to "".
    branding: logoDraft !== undefined ? { ...branding, logo_data: logoDraft } : null,
  }
}

export function planHasChanges(plan: GeneralSavePlan): boolean {
  return plan.orgChanges !== null || plan.general !== null || plan.branding !== null
}
