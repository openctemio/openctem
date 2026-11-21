/**
 * The built-in roles (owner, admin, member, viewer) are named and described by
 * the server in English. Their name and description follow the console
 * language here, by slug; a custom role keeps what its author wrote.
 */

type TFn = (key: string, fallback: string) => string

interface RoleText {
  slug?: string
  name: string
  description?: string
  is_system?: boolean
}

const SYSTEM_ROLE: Record<string, { name: string; description: string }> = {
  owner: { name: 'Owner', description: 'Full access to everything including team management' },
  admin: { name: 'Administrator', description: 'Administrative access to most resources' },
  member: {
    name: 'Member',
    description: 'Standard member with read/write access to assigned resources',
  },
  viewer: { name: 'Viewer', description: 'Read-only access to assigned resources' },
}

function builtIn(role: RoleText): string | undefined {
  return role.is_system && role.slug && SYSTEM_ROLE[role.slug] ? role.slug : undefined
}

/** A role's name: a built-in role in the console language, a custom role as named. */
export function roleDisplayName(t: TFn, role: RoleText): string {
  const slug = builtIn(role)
  return slug ? t(`org.systemRole.${slug}`, SYSTEM_ROLE[slug].name) : role.name
}

/** A role's description: a built-in role's in the console language. */
export function roleDisplayDescription(t: TFn, role: RoleText): string | undefined {
  const slug = builtIn(role)
  return slug
    ? t(`org.systemRoleDescription.${slug}`, SYSTEM_ROLE[slug].description)
    : role.description || undefined
}
