import { describe, expect, it } from 'vitest'
import { attributeValueLabel, hasValueLabels, kindSourceConfidence } from './attribute-values'

describe('attribute value labels', () => {
  it('labels service kinds, categories and sources in the viewer language', () => {
    expect(attributeValueLabel('service_kind', 'mssql', 'en')).toBe('Microsoft SQL Server')
    expect(attributeValueLabel('service_kind', 'docker-api', 'en')).toBe('Docker API')
    expect(attributeValueLabel('service_category', 'remote_access', 'en')).toBe('Remote access')
    expect(attributeValueLabel('service_category', 'remote_access', 'vi')).toBe('Truy cập từ xa')
    expect(attributeValueLabel('kind_source', 'port_guess', 'en')).toBe('Guessed from the port')
  })

  it('shows any other value as stored', () => {
    expect(attributeValueLabel('service_kind', 'not-a-kind', 'en')).toBe('not-a-kind')
    expect(attributeValueLabel('service_kind', '__proto__', 'en')).toBe('__proto__')
    expect(attributeValueLabel('os_family', 'linux', 'en')).toBe('linux')
    expect(hasValueLabels('service_kind')).toBe(true)
    expect(hasValueLabels('os_family')).toBe(false)
  })

  it('ranks a port guess lowest', () => {
    expect(kindSourceConfidence('fingerprint')).toBeGreaterThan(
      kindSourceConfidence('port_guess') ?? 100
    )
    expect(kindSourceConfidence('nope')).toBeUndefined()
  })
})
