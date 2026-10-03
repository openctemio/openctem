import { describe, it, expect } from 'vitest'
import { editableProperties } from '../use-assets'

describe('editableProperties', () => {
  it('drops the API-owned keys a loaded asset carries', () => {
    expect(
      editableProperties({
        is_crown_jewel: true,
        business_impact_score: 80,
        business_impact_notes: 'n',
        aliases: ['old.example.com'],
        discovery_source: 'dns',
        discovery_tool: 'subfinder',
        __promoted_sub_type: 'x',
        registrar: 'acme',
      })
    ).toEqual({ registrar: 'acme' })
  })

  it('returns undefined when nothing editable is left', () => {
    expect(editableProperties({ is_crown_jewel: true })).toBeUndefined()
    expect(editableProperties({})).toBeUndefined()
    expect(editableProperties(undefined)).toBeUndefined()
  })
})
