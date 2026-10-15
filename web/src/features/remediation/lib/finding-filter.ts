// Edit keeps the campaign's other scope conditions (cve, asset, severity…) and
// only replaces its linked findings. A campaign tracked by a fix
// (remediation_key) has no linked findings: its scope is left untouched.
export function mergeFindingFilter(
  original: Record<string, unknown> | null | undefined,
  linked: Record<string, unknown> | undefined
): Record<string, unknown> | undefined {
  if (!linked) return undefined
  if (original?.remediation_key) return undefined
  return { ...(original ?? {}), ...linked }
}
