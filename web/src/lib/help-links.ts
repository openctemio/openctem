import {
  DEFAULT_BUG_URL,
  DEFAULT_FEEDBACK_URL,
  DEFAULT_HELP_LINKS,
  DEFAULT_SECURITY_URL,
  type HelpLinks,
} from '@/config/help-links'
import { httpsOnly } from '@/lib/brand'
import { securityContactUri } from '@/lib/legal'

/** The help fields of the API's public GET /api/v1/legal. */
export interface HelpSettingsResponse {
  help_bug_url?: string
  help_feedback_url?: string
  help_links_disabled?: boolean
  security_contact?: string
  security_policy_url?: string
}

/**
 * Resolves the links from the operator's settings, value by value: an
 * operator link must be https (anything else keeps the default); the security
 * entry takes the operator's policy link, else their contact (mailto: or
 * https), else the project's security policy.
 */
export function resolveHelpLinks(r: HelpSettingsResponse | null | undefined): HelpLinks {
  if (!r || typeof r !== 'object') return DEFAULT_HELP_LINKS
  const bug = httpsOnly(r.help_bug_url)
  const security =
    httpsOnly(r.security_policy_url) ||
    securityContactUri(typeof r.security_contact === 'string' ? r.security_contact : '') ||
    DEFAULT_SECURITY_URL
  return {
    bugUrl: bug || DEFAULT_BUG_URL,
    feedbackUrl: httpsOnly(r.help_feedback_url) || DEFAULT_FEEDBACK_URL,
    securityUrl: security,
    hidden: r.help_links_disabled === true,
    bugIsDefault: !bug,
  }
}
