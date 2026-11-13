'use client'

import dynamic from 'next/dynamic'

// Two branches of the dashboard layout that most sessions never render: the slim
// account shell (no organization open) and the confirm-a-social-link prompt
// (only after a refused sign-in). A next/dynamic call in the server layout is
// still preloaded with it, so the loading happens here, in a client module: the
// code downloads when the branch first renders, not with every dashboard route.
// The account shell wraps the page, so it still renders on the server.
export const LazyAccountShell = dynamic(() =>
  import('@/features/account/components/account-shell').then((m) => m.AccountShell)
)

export const LazyPendingLinkPrompt = dynamic(
  () =>
    import('@/features/account/components/pending-link-prompt').then((m) => m.PendingLinkPrompt),
  { ssr: false }
)
