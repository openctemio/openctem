/**
 * The extension registered with this build (api/docs/development/editions.md,
 * "Web"). `@extension/web` is the stub in the default build and the mounted extension in an
 * extension build; nothing else in the tenant app imports it.
 */
import { extension } from '@extension/web'

import { assertCompatible, assertExtensionName } from './merge'

assertCompatible('extension @extension/web', extension.apiVersion)
assertExtensionName(extension.name)

/** The tenant app's extension (empty in the default build). */
export const webExtension = extension

export { EXTENSION_API_VERSION } from './types'
export type * from './types'
