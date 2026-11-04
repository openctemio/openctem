/**
 * The grant answer the navigation merges use. The app has no client-side
 * read of an organization's (or installation's) grants yet, so every grant is
 * off: a build with an extension lists its rows only once this reads the
 * grants the API reports, and the default build never has a row to list. The
 * API gate (permission + grant) is the boundary either way; this only hides.
 */
import type { GrantCheck } from './merge'

export const isGrantOn: GrantCheck = () => false
