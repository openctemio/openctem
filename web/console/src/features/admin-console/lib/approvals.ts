/** Words for four-eyes approval actions and targets (Security > Approvals). */

type Translate = (key: string, fallback: string, vars?: Record<string, string | number>) => string

const ACTION_FALLBACK: Record<string, string> = {
  'admin.grant_super_admin': 'Make a super admin',
  'admin.revoke_super_admin': 'Remove a super admin',
  'console_mfa.disable': 'Stop requiring security keys',
  'platform_idp.remove': "Remove or relax the administrators' identity provider",
  'platform_idp.change':
    "Change the administrators' identity provider or the second factor it is trusted for",
  'admin.reset_credentials': "Reset another administrator's console second factor",
  'signup.open': 'Open sign-up',
  'audit_chain.rebaseline': "Re-sign an organization's audit chain",
  'organization.purge': 'Delete an organization now',
}

/** The protected action in words. */
export function approvalActionLabel(action: string, t: Translate): string {
  const fallback = ACTION_FALLBACK[action]
  return fallback ? t(`admin.approvals.action.${action}`, fallback) : action
}

const IDP_TARGETS: Record<string, string> = {
  remove: 'Remove the identity provider',
  disable: 'Switch the identity provider off',
  require_idp_off: 'Stop requiring the identity provider',
}

const SIGNUP_MODES: Record<string, string> = {
  admin_only: 'only administrators create organizations',
  self_service: 'anyone may create an organization',
}

const SIGNUP_ACCOUNTS: Record<string, string> = {
  closed: 'no public accounts',
  domain: 'accounts on verified domains',
  open: 'anyone may create an account',
}

/** The exact target in words; the label comes from the server. */
export function approvalTargetLabel(
  a: { target: string; target_label?: string },
  t: Translate
): string {
  const { target } = a
  if (a.target_label) return a.target_label
  if (target.startsWith('email:')) return target.slice('email:'.length)
  if (target === 'off') return t('admin.approvals.target.off', 'Security keys no longer required')
  if (IDP_TARGETS[target]) return t(`admin.approvals.target.${target}`, IDP_TARGETS[target])
  const idpChange = platformIdPChangeLabel(target, t)
  if (idpChange) return idpChange
  const signup = /^mode=([a-z_]+);accounts=([a-z_]+)$/.exec(target)
  if (signup) {
    const mode = SIGNUP_MODES[signup[1]]
    const accounts = SIGNUP_ACCOUNTS[signup[2]]
    return t('admin.approvals.target.signup', '{mode}; {accounts}', {
      mode: mode ? t(`admin.approvals.signupMode.${signup[1]}`, mode) : signup[1],
      accounts: accounts ? t(`admin.approvals.signupAccounts.${signup[2]}`, accounts) : signup[2],
    })
  }
  return target
}

/** A platform_idp.change target: the new issuer, client and trusted values. */
function platformIdPChangeLabel(target: string, t: Translate): string | null {
  if (/^sha256:[0-9a-f]{64}$/.test(target)) {
    return t(
      'admin.approvals.target.platformIdpChangeHash',
      'Identity provider configuration {hash} (described in the reason)',
      { hash: target.slice('sha256:'.length, 'sha256:'.length + 12) }
    )
  }
  if (!target.startsWith('{"issuer":')) return null
  try {
    const c = JSON.parse(target) as {
      issuer?: string
      client_id?: string
      trusted_acr?: string[]
      trusted_amr?: string[]
    }
    const none = t('admin.approvals.target.none', 'none')
    return t(
      'admin.approvals.target.platformIdpChange',
      'Issuer {issuer}, client {client}; trusted ACR: {acr}; trusted AMR: {amr}',
      {
        issuer: c.issuer ?? '',
        client: c.client_id ?? '',
        acr: c.trusted_acr?.length ? c.trusted_acr.join(', ') : none,
        amr: c.trusted_amr?.length ? c.trusted_amr.join(', ') : none,
      }
    )
  } catch {
    return null
  }
}
