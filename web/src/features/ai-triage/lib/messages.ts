/**
 * Translated texts for AI triage states (API docs: architecture/ai-triage.md).
 *
 * The API never sends raw error text: a failed triage carries a failure code
 * (`error_code`), a refused request an error code (`AI_DISABLED`, ...), and
 * a reason in the config. Each maps to one translated message here.
 */
type T = (key: string, fallback: string, vars?: Record<string, string | number>) => string

/** Failure codes of a failed triage and their English text. */
const FAILURES: Record<string, string> = {
  internal_error: 'Something went wrong on our side. Try again later.',
  ai_policy_restricted:
    'Your organization’s AI data policy keeps this finding away from AI (pentest campaign above the TLP limit for AI, or AI turned off for the campaign).',
  ai_disabled: 'AI triage was turned off for this organization.',
  provider_not_configured: 'The AI provider is not set up correctly. Contact your administrator.',
  provider_rate_limited: 'The AI service is busy. Try again in a few minutes.',
  provider_auth_failed: 'The AI provider refused the key. Contact your administrator.',
  provider_quota_exceeded: 'The AI provider’s quota is used up. Contact your administrator.',
  provider_timeout: 'The AI service took too long to answer. Try again.',
  provider_unavailable: 'The AI service is unavailable. Try again later.',
  content_blocked: 'The AI provider’s content filter blocked this finding.',
  input_too_large: 'This finding is too large for AI analysis.',
  invalid_response: 'The AI returned an answer that could not be read. Try again.',
  empty_response: 'The AI returned an empty answer. Try again.',
  budget_exhausted: 'This organization used its monthly AI allowance.',
  budget_unavailable: 'The AI allowance could not be checked. Try again later.',
  token_limit_exceeded: 'This organization used its monthly AI allowance.',
  enqueue_failed: 'The analysis could not be queued. Try again.',
  stuck_timeout: 'The analysis did not finish in time. Try again.',
  finding_not_available: 'The finding is no longer available.',
  ai_use_case_off: 'The triage use case was turned off for this organization.',
  nothing_to_send:
    'Nothing in this finding may be sent to AI under the triage use case’s data setting.',
}

/** The translated message of a failure code (unknown codes read as generic). */
export function triageFailureMessage(t: T, code: string | undefined): string {
  const key = code && code in FAILURES ? code : 'internal_error'
  return t(`findings.aiTriage.failure.${key}`, FAILURES[key])
}

/** Request error codes the API answers when AI triage cannot start. */
const REQUEST_ERRORS: Record<string, string> = {
  AI_DISABLED:
    'AI triage is turned off for this organization. An organization administrator turns it on in Settings > AI.',
  AI_PLATFORM_NOT_CONFIGURED:
    'AI is not set up on this installation. A platform administrator sets up the AI provider in the console.',
  AI_OWN_PROVIDER_NOT_ALLOWED:
    'The platform does not allow organizations to use their own AI provider. An organization administrator switches the AI source to the platform in Settings > AI.',
  AI_POLICY_RESTRICTED: FAILURES.ai_policy_restricted,
  AI_USE_CASE_OFF:
    'AI triage is turned off for this organization. An owner or administrator turns it on in Settings > AI > Use cases.',
  CONFLICT: 'An analysis is already running for this finding.',
  RATE_LIMIT_EXCEEDED: 'Too many AI triage requests. Wait a minute and try again.',
}

/** The translated message of a refused triage request, or undefined. */
export function triageRequestErrorMessage(t: T, code: string | undefined): string | undefined {
  if (!code || !(code in REQUEST_ERRORS)) return undefined
  return t(`findings.aiTriage.requestError.${code}`, REQUEST_ERRORS[code])
}
