/**
 * The extension registered with this build (api/docs/development/editions.md,
 * "Web"). `@extension/web` is the stub in the default build and the overlay in an
 * extension build; nothing else in the tenant app imports it.
 */
import { extension } from '@extension/web'

import { assertCompatible, assertEditionName } from './merge'

assertCompatible('extension @extension/web', extension.apiVersion)
assertEditionName(extension.edition)

/** The tenant app's extension (empty in the default build). */
export const webExtension = extension

export { COMMUNITY_EDITION, EXTENSION_API_VERSION } from './types'
export type * from './types'
