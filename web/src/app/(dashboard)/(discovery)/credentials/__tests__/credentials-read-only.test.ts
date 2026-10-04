import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Owner decision D-17: there is no create, edit or delete endpoint for
// credentials, so the Credentials page is read-only. Its old Add dialog threw
// away what the user typed, and Edit/Delete were disabled "Coming soon"
// buttons. This pins that none of them come back until the backend exists.

const source = readFileSync(join(__dirname, '..', 'page.tsx'), 'utf8')

describe('Credentials page is read-only', () => {
  it('has no Add credential control or dialog', () => {
    expect(source).not.toMatch(/Add credential/i)
    expect(source).not.toMatch(/setAddDialogOpen/)
  })

  it('has no Edit or Delete controls', () => {
    expect(source).not.toMatch(/label: 'Edit'/)
    expect(source).not.toMatch(/label: 'Delete'/)
    expect(source).not.toMatch(/ConfirmDialog/)
    expect(source).not.toMatch(/Coming soon/i)
  })

  it('turns off the detail sheet edit and delete actions', () => {
    expect(source).toMatch(/canEdit=\{false\}/)
    expect(source).toMatch(/canDelete=\{false\}/)
  })

  it('keeps the working lifecycle action and the list', () => {
    expect(source).toMatch(/Mark resolved/)
    expect(source).toMatch(/useCredentialsApi\(/)
  })
})
