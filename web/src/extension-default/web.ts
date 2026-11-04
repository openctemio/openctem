/**
 * The default build's `@extension/web`: no extension, so nothing is added to the
 * tenant app (api/docs/development/editions.md, "Web").
 */
import { EXTENSION_API_VERSION, type WebExtension } from '@/lib/extension/types'

export const extension: WebExtension = {
  apiVersion: EXTENSION_API_VERSION,
  name: 'community',
  navItems: [],
  settingsItems: [],
  slots: {},
  overrides: {},
}
