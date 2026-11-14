/**
 * An edit of an asset's tags is sent as a change, never as a new list: the
 * tags the person added and the ones they removed, compared with the tags
 * they were shown. The API applies it to the stored tags, so a tag a sensor,
 * an import, a rule or another person set after the copy was loaded stays.
 */
export interface TagChange {
  tagsAdd: string[]
  tagsRemove: string[]
}

/** The change from the tags shown to the tags the person ended with. */
export function tagChange(shown: readonly string[], next: readonly string[]): TagChange {
  const before = new Set(shown)
  const after = new Set(next)
  return {
    tagsAdd: [...after].filter((t) => !before.has(t)),
    tagsRemove: [...before].filter((t) => !after.has(t)),
  }
}

/** Whether the change adds or removes anything. */
export function isEmptyTagChange(c: TagChange): boolean {
  return c.tagsAdd.length === 0 && c.tagsRemove.length === 0
}
