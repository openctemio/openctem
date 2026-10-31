import { describe, expect, it } from 'vitest'

import { taskContentNote } from '../run-tasks-table'

describe('taskContentNote', () => {
  it('names the pack version, the learned labels and the organization lists with versions', () => {
    expect(
      taskContentNote({
        content_pins: {
          packs: [
            { slot: 'labels', pack: 'wordlists-s', version: '2026.10.1', digest: 'sha256:x' },
          ],
          inputs: [
            { source: 'learned', lines: 177, sha256: 'a' },
            {
              source: 'organization',
              lines: 37,
              sha256: 'b',
              lists: [{ name: 'branches', version: 3 }],
            },
          ],
        },
      })
    ).toBe('Wordlists: wordlists-s 2026.10.1, 177 learned, 37 from your lists (branches v3)')
  })

  it('is null for a task that pinned nothing', () => {
    expect(taskContentNote({})).toBeNull()
    expect(taskContentNote({ content_pins: null })).toBeNull()
    expect(taskContentNote({ content_pins: { packs: [], inputs: [] } })).toBeNull()
  })
})
