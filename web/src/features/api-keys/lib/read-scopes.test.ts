import { describe, it, expect } from 'vitest'
import { API_KEY_SCOPES } from '../components/generate-key-dialog'

// API keys are read-only: the dialog offers read scopes only.
describe('API_KEY_SCOPES', () => {
  it('offers only read scopes', () => {
    expect(API_KEY_SCOPES.length).toBeGreaterThan(0)
    for (const s of API_KEY_SCOPES) expect(s.endsWith(':read')).toBe(true)
  })
})
