import { describe, expect, it } from 'vitest'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import { formFieldsForType, propertiesFromForm } from './type-form'

// A service's kind is set by the platform: the form never offers or sends it.
const service: TypeView = {
  type: 'service',
  label: 'Service',
  plural: 'Services',
  attributes: [
    { key: 'service_kind', kind: 'enum', values: ['rdp', 'ssh'], facet: true, derived: true },
    {
      key: 'kind_source',
      kind: 'enum',
      values: ['fingerprint', 'port_guess'],
      facet: true,
      derived: true,
    },
    { key: 'port', kind: 'int', facet: true },
  ],
  columns: [],
  facets: [],
  scannable: true,
}

describe('type form, derived attributes', () => {
  it('offers no field for a derived attribute', () => {
    const names = formFieldsForType(service).map((f) => f.name)
    expect(names).not.toContain('service_kind')
    expect(names).not.toContain('kind_source')
    expect(names).toContain('port')
  })

  it('never sends a derived attribute', () => {
    const props = propertiesFromForm(service, {
      service_kind: 'rdp',
      kind_source: 'fingerprint',
      port: '3389',
    })
    expect(props).not.toHaveProperty('service_kind')
    expect(props).not.toHaveProperty('kind_source')
    expect(props).toHaveProperty('port')
  })
})
