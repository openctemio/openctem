/**
 * Where the Help menu, the command palette and the error pages send a person
 * who wants to report something (documentation links live in
 * src/lib/docs-links.ts). An operator can repoint or hide the bug and feedback
 * entries in the admin console (System > Legal); the defaults below are the
 * project's own issue forms.
 */

/** New issue on the platform repository (openctemio/openctem: the API and the web console). */
export const REPORT_ISSUE_URL = 'https://github.com/openctemio/openctem/issues/new'

/** The issue forms in .github/ISSUE_TEMPLATE; their field ids are the prefill parameters. */
export const BUG_TEMPLATE = 'bug.yml'
export const FEATURE_TEMPLATE = 'feature.yml'

export const DEFAULT_BUG_URL = `${REPORT_ISSUE_URL}?template=${BUG_TEMPLATE}`
export const DEFAULT_FEEDBACK_URL = `${REPORT_ISSUE_URL}?template=${FEATURE_TEMPLATE}`

/**
 * A vulnerability is never reported in a public issue: this is the project's
 * security policy (SECURITY.md: private advisory or security@openctem.io).
 */
export const DEFAULT_SECURITY_URL = 'https://github.com/openctemio/openctem/security/policy'

/** The resolved links of this installation (see resolveHelpLinks). */
export interface HelpLinks {
  bugUrl: string
  feedbackUrl: string
  /** https URL or mailto: of the security policy or contact. Always present. */
  securityUrl: string
  /** The operator hid the bug and feedback entries and the error pages' report link. */
  hidden: boolean
  /** The bug link is the project's issue form (the only one safe diagnostics are prefilled into). */
  bugIsDefault: boolean
}

export const DEFAULT_HELP_LINKS: HelpLinks = {
  bugUrl: DEFAULT_BUG_URL,
  feedbackUrl: DEFAULT_FEEDBACK_URL,
  securityUrl: DEFAULT_SECURITY_URL,
  hidden: false,
  bugIsDefault: true,
}
