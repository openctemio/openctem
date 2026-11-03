/**
 * The default build's `@extension/web`: no extension, so nothing is added to the
 * tenant app (api/docs/development/editions.md, "Web").
 */
import { COMMUNITY_EDITION, EXTENSION_API_VERSION, type WebExtension } from '@/lib/extension/types'

export const extension: WebExtension = {
  apiVersion: EXTENSION_API_VERSION,
  edition: COMMUNITY_EDITION,
  navItems: [],
  settingsItems: [],
  slots: {},
  overrides: {},
}
