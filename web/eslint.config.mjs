import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Ignore coverage and sentry configs
    "coverage/**",
    "sentry-configs/**",
    // Git worktrees and stale build dirs are whole extra checkouts of this
    // repo, so linting them reports every file two or three times. CI never
    // sees them (fresh checkout), but locally `npx eslint .` returned 42,786
    // results against 40 real ones — enough noise to bury the real ones, which
    // is exactly what happened while investigating the six errors this commit
    // fixes.
    ".claude/**",
    ".next.*/**",
  ]),
  // Global rules
  {
    rules: {
      // Allow underscore-prefixed unused vars (intentional pattern for future use)
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      // Allow setState in effects - common pattern for syncing with external state
      // (localStorage, cookies, server data). React Compiler handles this well.
      "react-hooks/set-state-in-effect": "off",
      // TanStack Table returns functions that can't be memoized - this is expected
      // The React Compiler handles this gracefully by skipping memoization
      "react-hooks/incompatible-library": "off",
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
      "src/app/(dashboard)/settings/**/*.{ts,tsx}",
      "src/app/(dashboard)/account/**/*.{ts,tsx}",
      "src/features/organization/**/*.{ts,tsx}",
      "src/features/access-control/**/*.{ts,tsx}",
      "src/features/integrations/**/*.{ts,tsx}",
      "src/features/template-sources/**/*.{ts,tsx}",
      "src/features/account/**/*.{ts,tsx}",
      "src/features/notifications/**/*.{ts,tsx}",
      "src/features/pentest/lib/**/*.{ts,tsx}",
    ],
    ignores: ["**/*.test.ts", "**/*.test.tsx", "**/__tests__/**"],
    rules: {
      "no-restricted-syntax": [
        "error",
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
    files: ["**/image-upload.tsx", "**/image-upload.jsx"],
    rules: {
      "@next/next/no-img-element": "off",
    },
  },
  // Allow `any` in test files (mocking often requires it)
  {
    files: ["**/*.test.ts", "**/*.test.tsx", "**/*.spec.ts", "**/*.spec.tsx"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  // Playwright e2e: `use` here is a fixture callback, not a React hook.
  // The react-hooks rule misfires on it, so we disable hooks linting for
  // this directory. These files never run in the React renderer.
  {
    files: ["e2e/**/*.ts", "playwright.config.ts"],
    rules: {
      "react-hooks/rules-of-hooks": "off",
      "react-hooks/exhaustive-deps": "off",
    },
  },
]);

export default eslintConfig;
