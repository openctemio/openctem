/**
 * System tags the platform derives from bug-bounty program links (RFC-065
 * §16.5): bug-bounty, source:<source>, platform:<platform>,
 * program:<platform>:<slug>, program-unattested.
 */

export interface ProgramTargetInfo {
  /** "<platform>/<slug>" of each linked program. */
  programs: string[]
  platforms: string[]
  unattested: boolean
}

export function programTargetInfo(systemTags: string[] | undefined): ProgramTargetInfo | null {
  if (!systemTags?.includes('bug-bounty')) return null
  const programs: string[] = []
  const platforms: string[] = []
  for (const tag of systemTags) {
    if (tag.startsWith('program:')) {
      const [, platform, slug] = tag.split(':')
      if (platform && slug) programs.push(`${platform}/${slug}`)
    } else if (tag.startsWith('platform:')) {
      platforms.push(tag.slice('platform:'.length))
    }
  }
  return { programs, platforms, unattested: systemTags.includes('program-unattested') }
}
