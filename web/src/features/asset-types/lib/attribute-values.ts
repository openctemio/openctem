/**
 * Labels of attribute values the registry names (docs/architecture/service-kinds.md):
 * a service's kind, its category and the source the kind came from. The
 * labels (English and Vietnamese) come from the generated registry, so a new
 * kind needs no web change. Any other value is shown as stored.
 */
import {
  KIND_SOURCES,
  SERVICE_CATEGORY_LABELS,
  SERVICE_KIND_LABELS,
  type RegistryValueLabel,
} from '../registry.generated'

const KIND_SOURCE_LABELS: Readonly<Record<string, RegistryValueLabel>> = Object.fromEntries(
  KIND_SOURCES.map((s) => [s.id, s])
)

const VALUE_LABELS: Readonly<Record<string, Readonly<Record<string, RegistryValueLabel>>>> = {
  service_kind: SERVICE_KIND_LABELS,
  service_category: SERVICE_CATEGORY_LABELS,
  kind_source: KIND_SOURCE_LABELS,
}

/** The kind source a port guess carries: always shown as a guess. */
export const KIND_SOURCE_GUESS = 'port_guess'

/** True when the attribute's values have registry labels. */
export function hasValueLabels(key: string): boolean {
  return Object.prototype.hasOwnProperty.call(VALUE_LABELS, key)
}

/** The label of an attribute value in the viewer's language, else the value. */
export function attributeValueLabel(key: string, value: string, locale?: string): string {
  const table = VALUE_LABELS[key]
  const entry =
    table && Object.prototype.hasOwnProperty.call(table, value) ? table[value] : undefined
  if (!entry) return value
  return locale?.startsWith('vi') && entry.labelVi ? entry.labelVi : entry.label
}

/** The confidence (1..100) of a kind source, undefined for an unknown one. */
export function kindSourceConfidence(source: string): number | undefined {
  return KIND_SOURCES.find((s) => s.id === source)?.confidence
}
