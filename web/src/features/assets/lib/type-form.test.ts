import { describe, expect, it } from 'vitest'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import {
  attributeFromForm,
  createInputFromForm,
  formFieldsForType,
  propertiesFromForm,
  updateInputFromForm,
} from './type-form'

const host: TypeView = {
  type: 'host',
  label: 'Host',
  plural: 'Hosts',
  attributes: [
    { key: 'os_family', kind: 'enum', values: ['linux', 'windows'], facet: true },
    { key: 'os_name', kind: 'string', facet: true },
    { key: 'ip_addresses', kind: 'list', facet: false },
    { key: 'is_virtual', kind: 'bool', facet: true },
    { key: 'cpu_count', kind: 'int', facet: false },
    { key: 'memory_gb', kind: 'number', facet: false },
    { key: 'whois', kind: 'object', facet: false },
  ],
  columns: [],
  facets: [],
  scannable: true,
}

describe('type form', () => {
  it('has a field per editable attribute, named by its schema key', () => {
    const fields = formFieldsForType(host)
    const names = fields.map((f) => f.name)
    expect(names).toEqual([
      'name',
      'description',
      'os_family',
      'os_name',
      'ip_addresses',
      'is_virtual',
      'cpu_count',
      'memory_gb',
      'tags',
    ])
    expect(fields.find((f) => f.name === 'os_family')?.options?.map((o) => o.value)).toEqual([
      'linux',
      'windows',
    ])
    // A yes/no attribute is a choice, so leaving it empty means "not known".
    expect(fields.find((f) => f.name === 'is_virtual')?.type).toBe('select')
    expect(fields.find((f) => f.name === 'os_name')?.label).toBe('Operating system')
  })

  it('converts values to the attribute kind and drops what is not one', () => {
    expect(attributeFromForm(host.attributes[3], 'true')).toBe(true)
    expect(attributeFromForm(host.attributes[3], 'false')).toBe(false)
    expect(attributeFromForm(host.attributes[3], '')).toBeUndefined()
    expect(attributeFromForm(host.attributes[4], '8')).toBe(8)
    expect(attributeFromForm(host.attributes[4], 'x')).toBeUndefined()
    expect(attributeFromForm(host.attributes[0], 'solaris')).toBeUndefined()
    expect(attributeFromForm(host.attributes[2], 'a, b')).toEqual(['a', 'b'])
    expect(attributeFromForm({ key: 'expires_at', kind: 'time', facet: false }, '2027-05-14')).toBe(
      '2027-05-14T00:00:00.000Z'
    )
  })

  it('creates with schema keys only, leaving empty fields out', () => {
    const input = createInputFromForm(host, {
      name: ' web-1 ',
      os_family: 'linux',
      os_name: '',
      is_virtual: '',
      cpu_count: 4,
      whois: 'ignored',
      tags: ['prod'],
    })
    expect(input.name).toBe('web-1')
    expect(input.type).toBe('host')
    expect(input.metadata).toEqual({ os_family: 'linux', cpu_count: 4 })
    expect(input.tags).toEqual(['prod'])
  })

  it('keeps an alias sub-type on create', () => {
    const iamUser: TypeView = { ...host, type: 'identity', subType: 'iam_user', attributes: [] }
    expect(createInputFromForm(iamUser, { name: 'alice' }).subType).toBe('iam_user')
  })

  it('on edit, sends null for a field emptied from a value it had', () => {
    expect(
      propertiesFromForm(host, { os_name: '', cpu_count: 8 }, { os_name: 'Ubuntu', cpu_count: 4 })
    ).toEqual({ os_name: null, cpu_count: 8 })
    const update = updateInputFromForm(host, { name: 'web-1', ownerRef: '' }, {})
    expect(update.ownerRef).toBe('')
  })
})
