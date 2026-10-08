/**
 * The create / edit form of an asset type, generated from its registry
 * attributes (research/77), and the request it sends. The form writes only
 * schema keys, so a hand-entered asset holds the same keys a scanner's does.
 *
 *  - enum → a select of the registry values; bool → Yes / No (left empty:
 *    not known, never "No"); int / number → a number; list → comma-separated
 *    values; time → a date, sent as RFC 3339 UTC; string → text;
 *  - object attributes (DNS records, WHOIS, rules) are scanner data and are
 *    not edited by hand.
 */
import type { TypeAttribute, TypeView } from '@/features/asset-types/lib/type-view'
import { propertyLabel, type AssetPropertyKey } from '@/features/asset-types/lib/property-schema'
import type { FormFieldConfig } from '../types/form-field.types'
import type {
  AssetMetadata,
  AssetScope,
  Criticality,
  CreateAssetInput,
  ExposureLevel,
  ImpactRating,
  UpdateAssetInput,
} from '../types'

function fieldFor(a: TypeAttribute, locale?: string): FormFieldConfig | null {
  const base = { name: a.key, label: propertyLabel(a.key, locale), isMetadata: true }
  switch (a.kind) {
    case 'object':
      return null
    case 'bool':
      return {
        ...base,
        type: 'select',
        placeholder: 'Not known',
        options: [
          { label: 'Yes', value: 'true' },
          { label: 'No', value: 'false' },
        ],
      }
    case 'enum':
      return {
        ...base,
        type: 'select',
        placeholder: 'Not known',
        options: (a.values ?? []).map((v) => ({ label: v, value: v })),
      }
    case 'int':
    case 'number':
      return { ...base, type: 'number' }
    case 'list':
      return { ...base, type: 'tags', placeholder: 'Comma-separated values', fullWidth: true }
    case 'time':
      return { ...base, type: 'text', placeholder: 'YYYY-MM-DD' }
    default:
      return { ...base, type: 'text' }
  }
}

/** The form fields of a type: name, description, its attributes, labels. */
export function formFieldsForType(view: TypeView, locale?: string): FormFieldConfig[] {
  const attributes = view.attributes
    .map((a) => fieldFor(a, locale))
    .filter((f): f is FormFieldConfig => f !== null)
  return [
    { name: 'name', label: 'Name', type: 'text', required: true, fullWidth: true },
    { name: 'description', label: 'Description', type: 'textarea', fullWidth: true },
    ...attributes,
    { name: 'tags', label: 'Labels', type: 'tags', placeholder: 'production, web' },
  ]
}

function blank(v: unknown): boolean {
  return (
    v === undefined ||
    v === null ||
    (typeof v === 'string' && v.trim() === '') ||
    (Array.isArray(v) && v.length === 0) ||
    (typeof v === 'number' && Number.isNaN(v))
  )
}

/** One form value as the property value of its attribute, or undefined. */
export function attributeFromForm(a: TypeAttribute, raw: unknown): unknown {
  if (blank(raw)) return undefined
  switch (a.kind) {
    case 'bool':
      return raw === true || raw === 'true'
        ? true
        : raw === false || raw === 'false'
          ? false
          : undefined
    case 'int': {
      const n = typeof raw === 'number' ? raw : Number(raw)
      return Number.isFinite(n) ? Math.trunc(n) : undefined
    }
    case 'number': {
      const n = typeof raw === 'number' ? raw : Number(raw)
      return Number.isFinite(n) ? n : undefined
    }
    case 'time': {
      const d = new Date(String(raw))
      return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
    }
    case 'list':
      return Array.isArray(raw)
        ? raw
        : String(raw)
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
    case 'enum':
      return a.values?.includes(String(raw)) ? String(raw) : undefined
    default:
      return String(raw).trim()
  }
}

/**
 * The properties a form sends. On create, empty fields are left out; on
 * edit, a field emptied from a value it had is sent as null, so the value
 * goes.
 */
export function propertiesFromForm(
  view: TypeView,
  data: Record<string, unknown>,
  previous?: AssetMetadata
): AssetMetadata {
  const out: Partial<Record<AssetPropertyKey, unknown>> = {}
  for (const a of view.attributes) {
    if (a.kind === 'object' || !(a.key in data)) continue
    const v = attributeFromForm(a, data[a.key])
    if (v !== undefined) out[a.key] = v
    else if (previous && !blank(previous[a.key])) out[a.key] = null
  }
  return out
}

/** The fields every asset form carries (AssetFormDialogShared), typed. */
function common(data: Record<string, unknown>) {
  const str = (k: string) => (typeof data[k] === 'string' ? (data[k] as string) : undefined)
  return {
    name: String(data.name ?? '').trim(),
    description: String(data.description ?? ''),
    tags: Array.isArray(data.tags) ? (data.tags as string[]) : [],
    criticality: str('criticality') as Criticality | undefined,
    scope: str('scope') as AssetScope | undefined,
    exposure: str('exposure') as ExposureLevel | undefined,
    ownerRef: str('ownerRef'),
    impactConfidentiality: str('impactConfidentiality') as ImpactRating | '' | undefined,
    impactIntegrity: str('impactIntegrity') as ImpactRating | '' | undefined,
    impactAvailability: str('impactAvailability') as ImpactRating | '' | undefined,
  }
}

/** POST /assets for a type's create form. */
export function createInputFromForm(
  view: TypeView,
  data: Record<string, unknown>
): CreateAssetInput {
  const c = common(data)
  const metadata = propertiesFromForm(view, data)
  return {
    name: c.name,
    type: view.type as CreateAssetInput['type'],
    ...(view.subType ? { subType: view.subType } : {}),
    description: c.description,
    criticality: c.criticality || 'medium',
    scope: c.scope || 'internal',
    exposure: c.exposure || 'unknown',
    ...(c.impactConfidentiality ? { impactConfidentiality: c.impactConfidentiality } : {}),
    ...(c.impactIntegrity ? { impactIntegrity: c.impactIntegrity } : {}),
    ...(c.impactAvailability ? { impactAvailability: c.impactAvailability } : {}),
    ownerRef: c.ownerRef || undefined,
    tags: c.tags,
    ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
  } as CreateAssetInput
}

/** PUT /assets/{id} for a type's edit form. */
export function updateInputFromForm(
  view: TypeView,
  data: Record<string, unknown>,
  previous: AssetMetadata
): UpdateAssetInput {
  const c = common(data)
  const metadata = propertiesFromForm(view, data, previous)
  return {
    name: c.name,
    description: c.description,
    // '' clears the owner: the API only touches owner_ref when it is sent.
    ownerRef: c.ownerRef ?? '',
    ...(c.criticality ? { criticality: c.criticality } : {}),
    ...(c.scope ? { scope: c.scope } : {}),
    ...(c.exposure ? { exposure: c.exposure } : {}),
    ...(c.impactConfidentiality !== undefined
      ? { impactConfidentiality: c.impactConfidentiality }
      : {}),
    ...(c.impactIntegrity !== undefined ? { impactIntegrity: c.impactIntegrity } : {}),
    ...(c.impactAvailability !== undefined ? { impactAvailability: c.impactAvailability } : {}),
    tags: c.tags,
    ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
  } as UpdateAssetInput
}
