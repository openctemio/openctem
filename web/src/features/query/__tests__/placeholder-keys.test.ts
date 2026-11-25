import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/queryInput.json'
import vi from '@/lib/i18n/dictionaries/vi/queryInput.json'
import type { QueryEntity } from '../api/query-api'

// Every list with Query mode shows its entity's placeholder, never a raw key
// (the scans list showed `queryInput.placeholder.scans`).
const ENTITIES: Record<QueryEntity, true> = { findings: true, assets: true, scans: true }

describe('query editor placeholders', () => {
  for (const entity of Object.keys(ENTITIES)) {
    it(`has a placeholder for ${entity} in English and Vietnamese`, () => {
      const key = `queryInput.placeholder.${entity}`
      expect((en as Record<string, string>)[key]).toBeTruthy()
      expect((vi as Record<string, string>)[key]).toBeTruthy()
    })
  }
})
