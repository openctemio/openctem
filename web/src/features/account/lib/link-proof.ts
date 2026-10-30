/**
 * The proof typed in the confirm dialog of a sign-in method change (link,
 * unlink, confirming a pending link): the authenticator code, else the
 * password. The API refuses a recovery code and any change without a proof
 * (API docs: architecture/social-login-linking.md).
 */

import type { StepUpProofInput } from '@/components/security'
import type { LinkProof } from '@/features/auth/actions/social-auth-actions'

/** The request body form of what the dialog collected; null for a recovery code. */
export function linkProofFrom(input: StepUpProofInput): LinkProof | null {
  switch (input.kind) {
    case 'totp':
      return { totp: input.code }
    case 'password':
      return { password: input.password }
    default:
      return null
  }
}

/** A refused proof the dialog shows in place, carrying the API code. */
export class LinkProofRefused extends Error {
  readonly code: string
  constructor(code: string) {
    super(code)
    this.name = 'LinkProofRefused'
    this.code = code
  }
}
