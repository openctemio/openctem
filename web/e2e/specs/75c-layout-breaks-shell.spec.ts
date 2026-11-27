import { layoutRoutes, layoutSignedOut } from '../helpers/layout-breaks'

/**
 * Layout breaks on the entry and the shell: the home dashboard, the pages a
 * person lands on first, and the pages opened signed out (their own browser
 * context, no session: the form and the link-from-an-e-mail states the scratch
 * stack can reach without mail). The checks are in helpers/layout-breaks.ts;
 * see 75a-layout-breaks-lists.spec.ts for the split.
 */
layoutRoutes('Layout breaks: entry and shell', { tag: ['@phone', '@shell'] }, [
  // The home: its dashboard snapshot gets long titles and big figures (richData).
  '/',
  '/my-work',
  '/scope',
  '/notifications',
  '/oauth/device',
])

layoutSignedOut({ tag: ['@phone', '@auth'] }, [
  '/forgot-password',
  '/reset-password',
  '/reset-password#token=synthetic-reset-token',
  '/set-password#token=synthetic-setup-token',
  '/verify-email',
  '/request-access',
  '/request-access/confirm',
])
