import { describe, expect, it } from 'vitest'
import {
  activeFilterCount,
  apiFilters,
  currentPreset,
  listValues,
  toggleListValue,
} from '../filters'

describe('component list filters', () => {
  it('splits and toggles comma lists', () => {
    expect(listValues(' npm, pypi ,,')).toEqual(['npm', 'pypi'])
    expect(toggleListValue('npm', 'pypi', true)).toBe('npm,pypi')
    expect(toggleListValue('npm,pypi', 'npm', false)).toBe('pypi')
    expect(toggleListValue('npm', 'npm', true)).toBe('npm')
  })

  it('counts every selected value', () => {
    expect(activeFilterCount({ ecosystem: 'npm,pypi', kev: 'true', license: '' })).toBe(3)
  })

  it('recognises presets only when the filters equal them', () => {
    expect(currentPreset({})).toBe('all')
    expect(currentPreset({ kev: 'true', ecosystem: '' })).toBe('kev')
    expect(currentPreset({ kev: 'true', ecosystem: 'npm' })).toBeNull()
    expect(currentPreset({ relationship: 'direct' })).toBe('direct')
  })

  it('sends only the set filters and the trimmed search', () => {
    expect(apiFilters({ ecosystem: 'npm', kev: '', severity: 'critical' }, '  lodash ')).toEqual({
      ecosystem: 'npm',
      severity: 'critical',
      q: 'lodash',
    })
  })
})
