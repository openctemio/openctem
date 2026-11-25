/**
 * i18n keys of the sidebar's labels, shared by the sidebar and the command
 * palette so both show a page under the same translated name.
 */

/** Maps a sidebar group title to its i18n key, e.g. "Scoping" → "nav.group.scoping". */
export function groupTitleKey(title: string): string {
  return `nav.group.${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
}

/** Maps a sidebar item title to its i18n key, e.g. "Attack Surface" → "nav.item.attack-surface". */
export function navItemKey(title: string): string {
  return `nav.item.${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
}
