import { defineConfig, globalIgnores } from 'eslint/config'
import nextVitals from 'eslint-config-next/core-web-vitals'
import nextTs from 'eslint-config-next/typescript'

// Console files that still hand-roll a pattern the shared kit covers (the
// console kit rule below). Remove a file from the list in the PR that moves
// it to the shared component; never add one.
const CONSOLE_KIT_ALLOWLIST = [
  // raw ui/table
  'console/src/features/admin-console/components/access-requests-panel.tsx',
  'console/src/features/admin-console/components/bundle-detail.tsx',
  'console/src/features/admin-console/components/organization-audit-chain-panel.tsx',
  'console/src/features/admin-console/components/organization-modules-panel.tsx',
  'console/src/features/admin-console/components/self-service-limits-form.tsx',
  'console/src/features/admin-console/components/signup-events-panel.tsx',
  'console/src/features/admin-console/components/support-session-view.tsx',
  // raw <table>
  'console/src/app/(console)/health/page.tsx',
  'console/src/app/(console)/system/content-packs/page.tsx',
  'console/src/app/(console)/users/[[]userId]/page.tsx',
  // tabs used as a filter
  'console/src/features/admin-console/components/add-content-pack-dialog.tsx',
  'console/src/app/(console)/system/configuration/page.tsx',
  'console/src/app/(console)/system/ai-applications/page.tsx',
  'console/src/app/(console)/users/page.tsx',
]

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    '.next/**',
    'out/**',
    'build/**',
    'next-env.d.ts',
    // Ignore coverage and sentry configs
    'coverage/**',
    'sentry-configs/**',
    // Git worktrees and stale build dirs are whole extra checkouts of this
    // repo, so linting them reports every file two or three times. CI never
    // sees them (fresh checkout), but locally `npx eslint .` returned 42,786
    // results against 40 real ones — enough noise to bury the real ones, which
    // is exactly what happened while investigating the six errors this commit
    // fixes.
    '.claude/**',
    '.next.*/**',
    'console/.next/**',
    'console/next-env.d.ts',
  ]),
  // The tenant app and the platform console are separate apps (RFC-022
  // revision 21): the tenant app never imports console code, and the console
  // never imports a tenant route (only shared components, hooks and libs).
  {
    files: ['src/**/*.{ts,tsx}'],
    // Tests may drive both apps (the cross-app CSRF gate test); they ship in
    // neither bundle.
    ignores: ['**/*.test.ts', '**/*.test.tsx', '**/__tests__/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@console/*', '**/console/src/**'],
              message: 'The tenant app must not import platform console code (web/console).',
            },
          ],
          paths: [
            {
              name: 'swr',
              importNames: ['mutate', 'preload'],
              message:
                "SWR's global mutate/preload reach only the default cache; the dashboard keeps one cache per organization epoch. Use mutate from '@/lib/swr-mutate' or useSWRConfig() (web/docs/organization-switch.md).",
            },
          ],
        },
      ],
    },
  },
  {
    files: ['console/src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@/app/*', '!@/app/providers'],
              message:
                'The console must not import tenant routes; move shared code out of src/app.',
            },
          ],
        },
      ],
    },
  },
  // One shared component per pattern (owner 2026-11-02): console pages and
  // components use the kit the tenant app uses (web/src/features/shared),
  // never a hand-rolled variant of a list table, a confirmation or a filter.
  // The pattern -> component map is web/docs/ui/shared-kit.md. A file that predates
  // the rule is listed in CONSOLE_KIT_ALLOWLIST until it is moved; the list
  // only shrinks.
  {
    files: ['console/src/app/**/*.tsx', 'console/src/features/**/*.tsx'],
    ignores: ['**/*.test.tsx', '**/__tests__/**', ...CONSOLE_KIT_ALLOWLIST],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@/app/*', '!@/app/providers'],
              message:
                'The console must not import tenant routes; move shared code out of src/app.',
            },
          ],
          paths: [
            {
              name: '@/components/ui/table',
              message:
                'Use the shared DataTable (@/features/shared): sorting, empty state, phone cards and keyboard-focusable scrolling come with it.',
            },
            {
              name: '@/components/ui/alert-dialog',
              message:
                'Use ConfirmDialog (@/components/confirm-dialog), or AdminConfirmDialog for a protected write.',
            },
          ],
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXOpeningElement[name.name='table']",
          message: 'Use the shared DataTable (@/features/shared), not a raw <table>.',
        },
        {
          selector:
            "ImportDeclaration[source.value='@/components/ui/tabs']:not(:has(ImportSpecifier[imported.name='TabsContent']))",
          message:
            'Tabs without panels are a filter: use FilterSelect (@/features/shared). Route tabs use SectionTabs.',
        },
      ],
    },
  },
  // Global rules
  {
    rules: {
      // Allow underscore-prefixed unused vars (intentional pattern for future use)
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      // Allow setState in effects - common pattern for syncing with external state
      // (localStorage, cookies, server data). React Compiler handles this well.
      'react-hooks/set-state-in-effect': 'off',
      // TanStack Table returns functions that can't be memoized - this is expected
      // The React Compiler handles this gracefully by skipping memoization
      'react-hooks/incompatible-library': 'off',
    },
  },
  // Edit payloads must be able to clear a field. `x || undefined` turns a
  // cleared value into "absent", which every PATCH/PUT treats as "unchanged",
  // so the clear was silently dropped behind a success toast (23a B16: role
  // and team description, template-source credential, ...). Send "" or null
  // instead, whichever the endpoint documents as "clear".
  {
    // Settings and account surfaces. Other areas still have this pattern and
    // are migrated area by area (each needs its endpoint's clear semantics
    // checked first); source credentials join with their own fix.
    files: [
      'src/app/(dashboard)/settings/**/*.{ts,tsx}',
      'src/app/(dashboard)/account/**/*.{ts,tsx}',
      'src/features/organization/**/*.{ts,tsx}',
      'src/features/access-control/**/*.{ts,tsx}',
      'src/features/integrations/**/*.{ts,tsx}',
      'src/features/template-sources/**/*.{ts,tsx}',
      'src/features/account/**/*.{ts,tsx}',
      'src/features/notifications/**/*.{ts,tsx}',
      'src/features/pentest/lib/**/*.{ts,tsx}',
    ],
    ignores: ['**/*.test.ts', '**/*.test.tsx', '**/__tests__/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "CallExpression[callee.name=/^(update|patch|put|edit)/] > ObjectExpression > Property > LogicalExpression[operator='||'][right.name='undefined']",
          message:
            "Do not send `x || undefined` in an update payload: a cleared field becomes 'unchanged'. Send '' or null to clear.",
        },
        {
          selector:
            "CallExpression[callee.property.name=/^(update|patch|put|edit)/] > ObjectExpression > Property > LogicalExpression[operator='||'][right.name='undefined']",
          message:
            "Do not send `x || undefined` in an update payload: a cleared field becomes 'unchanged'. Send '' or null to clear.",
        },
        {
          selector:
            "VariableDeclarator[id.typeAnnotation.typeAnnotation.typeName.name=/^Update.*(Request|Input)$/] > ObjectExpression > Property > LogicalExpression[operator='||'][right.name='undefined']",
          message:
            "Do not send `x || undefined` in an update payload: a cleared field becomes 'unchanged'. Send '' or null to clear.",
        },
      ],
    },
  },
  // Allow <img> in image upload components (for user-uploaded content)
  {
    files: ['**/image-upload.tsx', '**/image-upload.jsx'],
    rules: {
      '@next/next/no-img-element': 'off',
    },
  },
  // Allow `any` in test files (mocking often requires it)
  {
    files: ['**/*.test.ts', '**/*.test.tsx', '**/*.spec.ts', '**/*.spec.tsx'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  // Playwright e2e: `use` here is a fixture callback, not a React hook.
  // The react-hooks rule misfires on it, so we disable hooks linting for
  // this directory. These files never run in the React renderer.
  {
    files: ['e2e/**/*.ts', 'playwright.config.ts'],
    rules: {
      'react-hooks/rules-of-hooks': 'off',
      'react-hooks/exhaustive-deps': 'off',
    },
  },
])

export default eslintConfig
