/**
 * Scan Utility Function Tests
 *
 * Tests for pure utility functions used by scan dialogs:
 * - parseTargets (QuickScanDialog)
 * (scanConfigToFormData and the schedule mapping are tested on the real code in
 * ../lib/__tests__/scan-form.test.ts.)
 * - getCompatibilityStatus
 */

import { describe, it, expect } from 'vitest'
import { getCompatibilityStatus } from '../types/scan.types'

// =============================================================================
// parseTargets — extracted from quick-scan-dialog.tsx
// =============================================================================

/** Parse targets from text, supporting newline, comma, and semicolon separators. */
function parseTargets(text: string): string[] {
  return text
    .split(/[\n,;]+/)
    .map((t) => t.trim())
    .filter(Boolean)
}

describe('parseTargets', () => {
  it('parses newline-separated targets', () => {
    expect(parseTargets('example.com\n192.168.1.1\nhttps://api.example.com')).toEqual([
      'example.com',
      '192.168.1.1',
      'https://api.example.com',
    ])
  })

  it('parses comma-separated targets', () => {
    expect(parseTargets('example.com,192.168.1.1,https://api.example.com')).toEqual([
      'example.com',
      '192.168.1.1',
      'https://api.example.com',
    ])
  })

  it('parses semicolon-separated targets', () => {
    expect(parseTargets('example.com;192.168.1.1;https://api.example.com')).toEqual([
      'example.com',
      '192.168.1.1',
      'https://api.example.com',
    ])
  })

  it('parses mixed separators', () => {
    expect(parseTargets('a.com\nb.com,c.com;d.com')).toEqual(['a.com', 'b.com', 'c.com', 'd.com'])
  })

  it('trims whitespace from targets', () => {
    expect(parseTargets('  example.com  ,  192.168.1.1  ')).toEqual(['example.com', '192.168.1.1'])
  })

  it('filters empty entries from consecutive separators', () => {
    expect(parseTargets('example.com,,192.168.1.1\n\n\ntest.com')).toEqual([
      'example.com',
      '192.168.1.1',
      'test.com',
    ])
  })

  it('returns empty array for empty string', () => {
    expect(parseTargets('')).toEqual([])
  })

  it('returns empty array for whitespace-only input', () => {
    expect(parseTargets('   \n   \n   ')).toEqual([])
  })

  it('returns empty array for only separators', () => {
    expect(parseTargets(',,,;;;')).toEqual([])
  })

  it('handles single target', () => {
    expect(parseTargets('example.com')).toEqual(['example.com'])
  })

  it('handles targets with ports', () => {
    expect(parseTargets('example.com:8080\n192.168.1.1:443')).toEqual([
      'example.com:8080',
      '192.168.1.1:443',
    ])
  })

  it('handles CIDR notation', () => {
    expect(parseTargets('192.168.1.0/24, 10.0.0.0/8')).toEqual(['192.168.1.0/24', '10.0.0.0/8'])
  })

  it('handles URLs with paths', () => {
    expect(parseTargets('https://api.example.com/v1\nhttps://app.example.com/login')).toEqual([
      'https://api.example.com/v1',
      'https://app.example.com/login',
    ])
  })
})

// =============================================================================
// getCompatibilityStatus — from scan.types.ts
// =============================================================================

describe('getCompatibilityStatus', () => {
  it('returns full for 100%', () => {
    expect(getCompatibilityStatus(100)).toBe('full')
  })

  it('returns full for >100% (edge case)', () => {
    expect(getCompatibilityStatus(150)).toBe('full')
  })

  it('returns partial for 50%', () => {
    expect(getCompatibilityStatus(50)).toBe('partial')
  })

  it('returns partial for 1%', () => {
    expect(getCompatibilityStatus(1)).toBe('partial')
  })

  it('returns partial for 99%', () => {
    expect(getCompatibilityStatus(99)).toBe('partial')
  })

  it('returns none for 0%', () => {
    expect(getCompatibilityStatus(0)).toBe('none')
  })

  it('returns none for negative (edge case)', () => {
    expect(getCompatibilityStatus(-1)).toBe('none')
  })
})
