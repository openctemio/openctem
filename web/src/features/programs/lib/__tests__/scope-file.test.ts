import { describe, expect, it } from 'vitest'
import {
  MAX_SCOPE_FILE_BYTES,
  csvHeaderColumns,
  scopeFileFromForm,
  scopeFileTooLarge,
} from '../program-form'

describe('csvHeaderColumns', () => {
  it('reads comma, semicolon and tab headers, quotes and BOM', () => {
    expect(csvHeaderColumns('Target,Kind,Eligible\na,b,c')).toEqual(['Target', 'Kind', 'Eligible'])
    expect(csvHeaderColumns('a;b;c,d\n')).toEqual(['a', 'b', 'c,d'])
    expect(csvHeaderColumns('﻿"identifier"\tasset_type\r\nx\ty')).toEqual([
      'identifier',
      'asset_type',
    ])
  })

  it('is empty for an empty file', () => {
    expect(csvHeaderColumns('')).toEqual([])
    expect(csvHeaderColumns('\n\n')).toEqual([])
  })
})

describe('scopeFileTooLarge', () => {
  it('counts UTF-8 bytes like the server', () => {
    expect(scopeFileTooLarge('a'.repeat(MAX_SCOPE_FILE_BYTES))).toBe(false)
    expect(scopeFileTooLarge('a'.repeat(MAX_SCOPE_FILE_BYTES + 1))).toBe(true)
    // Two bytes per character.
    expect(scopeFileTooLarge('é'.repeat(MAX_SCOPE_FILE_BYTES / 2 + 1))).toBe(true)
  })
})

describe('scopeFileFromForm', () => {
  const base = {
    fileName: 'scope.csv',
    fileContent: 'Target\nexample.com\n',
    mapIdentifier: 'Target',
    mapType: '',
    mapInScope: 'Eligible',
  }

  it('sends a mapping only for a generic CSV, without empty columns', () => {
    expect(scopeFileFromForm({ ...base, fileFormat: 'generic_csv' })).toEqual({
      format: 'generic_csv',
      name: 'scope.csv',
      content: base.fileContent,
      mapping: { identifier: 'Target', in_scope: 'Eligible' },
    })
    expect(scopeFileFromForm({ ...base, fileFormat: 'burp_json' }).mapping).toBeUndefined()
  })
})
