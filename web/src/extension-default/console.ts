/** The default build's `@extension/console`: nothing is added to the console. */
import { EXTENSION_API_VERSION, type ConsoleExtension } from '@/lib/extension/types'

export const extension: ConsoleExtension = {
  apiVersion: EXTENSION_API_VERSION,
  navItems: [],
}
