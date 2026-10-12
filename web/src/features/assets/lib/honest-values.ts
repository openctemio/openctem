/**
 * Export a recorded boolean as "Yes" / "No", and an unrecorded one as an
 * empty cell. `v ? 'Yes' : 'No'` turned "nobody checked" into "No" for MFA,
 * encryption and public access, a false negative on a security control.
 */
export function yesNoUnknown(v: unknown): string {
  if (v === true) return 'Yes'
  if (v === false) return 'No'
  return ''
}
