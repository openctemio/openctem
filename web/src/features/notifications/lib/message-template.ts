/**
 * Channel message settings shared by the add and edit dialogs: the detail
 * levels, the template variables (the API's closed set: a template naming
 * anything else is refused on save) and the presets. The preview is
 * rendered by the API from sample data, with the same code that builds real
 * messages, so what the dialog shows is what the channel gets.
 */

export const DETAIL_LEVELS = ['minimal', 'standard', 'full'] as const
export type DetailLevel = (typeof DETAIL_LEVELS)[number]
export const DEFAULT_DETAIL_LEVEL: DetailLevel = 'standard'

/** The template variables, in the order the editor lists them. */
export const TEMPLATE_VARIABLES = [
  'title',
  'severity',
  'asset',
  'asset_type',
  'what',
  'why',
  'next_step',
  'organization',
  'count',
  'description',
] as const

/** Presets use only the variables above; '' means the default layout. */
export const TEMPLATE_PRESETS = [
  { id: 'default', template: '' },
  { id: 'short', template: '{asset}: {what}\n{next_step}' },
  { id: 'triage', template: '{what}\n{why}\n{next_step}\n{organization}' },
  { id: 'custom', template: null },
] as const

export type TemplatePresetId = (typeof TEMPLATE_PRESETS)[number]['id']

/** The preset a stored template matches, or custom. */
export function presetOf(template: string | undefined): TemplatePresetId {
  const value = template ?? ''
  const found = TEMPLATE_PRESETS.find((p) => p.template === value)
  return found ? found.id : 'custom'
}

/** A stored level, with anything unknown read as the default. */
export function detailLevelOf(value: string | undefined): DetailLevel {
  return (DETAIL_LEVELS as readonly string[]).includes(value ?? '')
    ? (value as DetailLevel)
    : DEFAULT_DETAIL_LEVEL
}
