'use client'

import { Main } from '@/components/layout'
import { CIGitHubCallback } from '@/features/ci-runners/components/ci-github-callback'

export default function GitHubAppCallbackPage() {
  return (
    <Main>
      <CIGitHubCallback />
    </Main>
  )
}
