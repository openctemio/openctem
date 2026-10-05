/**
 * research/22 P0-13: every exposure type the API can emit renders with a
 * label (Exposures list, filters and the EASM overview). The list is read
 * from the API's own declaration so a new type cannot ship unlabeled.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { EVENT_TYPE_CONFIG, type ExposureEventType } from '../exposure-types'
import { EXPOSURE_EVENT_TYPE_LABELS } from '@/features/exposures/components/exposure-table'

function apiEventTypes(): string[] {
  const src = readFileSync(
    resolve(__dirname, '../../../../../api/pkg/domain/exposure/value_objects.go'),
    'utf8'
  )
  return [...src.matchAll(/EventType[A-Za-z]+\s+EventType = "([a-z_]+)"/g)].map((m) => m[1])
}

describe('exposure types', () => {
  const types = apiEventTypes()

  it('reads the API declaration', () => {
    expect(types.length).toBeGreaterThan(20)
    expect(types).toContain('dangling_cname')
  })

  it('labels every type the API emits', () => {
    for (const t of types) {
      expect(EVENT_TYPE_CONFIG[t as ExposureEventType]?.label, t).toBeTruthy()
      expect(EXPOSURE_EVENT_TYPE_LABELS[t as ExposureEventType], t).toBeTruthy()
    }
  })
})
