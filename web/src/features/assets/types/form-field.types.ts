/**
 * One field of the shared asset form (AssetFormDialogShared). The inventory
 * generates the fields of a type from its registry attributes
 * (lib/type-form); `name` is then the property key.
 */
export interface FormFieldConfig {
  /** Field name: a property key for a metadata field, else an asset field. */
  name: string

  /** Display label */
  label: string

  /** Field type determines the input component */
  type: 'text' | 'textarea' | 'select' | 'number' | 'tags' | 'boolean'

  /** Placeholder text */
  placeholder?: string

  /** Whether this field is required */
  required?: boolean

  /** Options for select fields */
  options?: { label: string; value: string }[]

  /** Whether this field maps to asset.metadata[name] vs top-level */
  isMetadata?: boolean

  /** Visual group label (for form layout) */
  group?: string

  /** Full width (span both columns) */
  fullWidth?: boolean

  /** Default value */
  defaultValue?: string | boolean | number
}
