/**
 * A dashboard name that is free among the person's dashboards (names are
 * unique per person, case-insensitive). `name` is used as-is when free;
 * otherwise `base` (default: `name`) gets " 2", " 3", ... appended.
 */
export function uniqueDashboardName(
  name: string,
  existing: readonly string[],
  base: string = name
): string {
  const taken = new Set(existing.map((n) => n.trim().toLowerCase()))
  let candidate = taken.has(name.toLowerCase()) ? base : name
  for (let n = 2; taken.has(candidate.toLowerCase()); n++) candidate = `${base} ${n}`
  return candidate
}
