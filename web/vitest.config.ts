import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'
import DurationSequencer from './vitest.sequencer'

export default defineConfig({
  plugins: [react()],
  test: {
    // Test environment
    environment: 'jsdom',

    // Setup files
    setupFiles: ['./src/test/setup.ts'],

    // @uiw/react-md-editor (4.2+) imports .css from its ESM build; Node cannot
    // load that, so Vite must process these packages.
    server: { deps: { inline: [/@uiw\//] } },

    // Global test utilities
    globals: true,

    // `--shard=i/n` balanced by recorded run time (VITEST_DURATIONS); Vitest's
    // own split when no durations are given.
    sequence: { sequencer: DurationSequencer },

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'src/test/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData',
        '**/.next',
      ],
    },

    // Include/exclude patterns
    include: ['**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    // These patterns need to be globbed, not bare directory names: a bare
    // 'node_modules' only matches the one at the root, so a git worktree under
    // .claude/ dragged its own node_modules — and a second copy of the app —
    // into every local run. That inflated the suite to ~16k tests and produced
    // hundreds of phantom failures from Playwright specs vitest cannot run,
    // which makes `npm test` untrustworthy exactly when you need it.
    exclude: [
      '**/node_modules/**',
      '**/.next/**',
      '**/dist/**',
      '**/build/**',
      '**/e2e/**',
      // git worktrees live here; they are separate checkouts, not this suite.
      '**/.claude/**',
    ],
  },
  resolve: {
    // `@extension/*` is the empty stub here; an extension's own test run points it
    // at the overlay with its own config (docs/development/editions.md).
    alias: [
      {
        find: /^@extension\/(.*)$/,
        replacement: path.resolve(__dirname, './src/extension-default/$1'),
      },
      { find: '@', replacement: path.resolve(__dirname, './src') },
      { find: '@console', replacement: path.resolve(__dirname, './console/src') },
    ],
  },
})
