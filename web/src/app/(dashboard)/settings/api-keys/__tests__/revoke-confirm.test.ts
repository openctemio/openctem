/**
 * Revoking an API key is irreversible and cuts off every client using it, so
 * it must go through a confirmation like Delete does (23a S1: Revoke fired on
 * the first click).
 */
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const src = readFileSync(
  join(process.cwd(), 'src/app/(dashboard)/settings/api-keys/page.tsx'),
  'utf8'
)

describe('API key revoke', () => {
  it('the Revoke button opens a confirmation instead of revoking', () => {
    expect(src).not.toMatch(/onClick=\{handleRevoke\}/)
    expect(src).toMatch(/onClick=\{\(\) => setRevokeOpen\(true\)\}/)
  })

  it('only the confirmation calls handleRevoke', () => {
    expect(src).toMatch(
      /open=\{revokeOpen\}[\s\S]*?handleConfirm=\{\(\) => void handleRevoke\(\)\}/
    )
  })

  it('error toasts carry the server reason', () => {
    expect(src).toMatch(/getErrorMessage\(error, 'Failed to revoke the key'\)/)
  })
})
