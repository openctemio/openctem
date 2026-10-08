# Architecture Deep Dive

> Detailed explanation of project structure and organization principles.

## Folder Structure

```
web/
├── src/
│   ├── app/                         # Next.js App Router: routing only
│   │   ├── (auth)/                  # login, register, forgot/reset/set-password,
│   │   │                            # select-tenant, onboarding
│   │   ├── (dashboard)/             # Signed-in console, grouped by CTEM stage
│   │   │   ├── (scoping)/ (discovery)/ (prioritization)/ (validation)/ (mobilization)/
│   │   │   ├── findings/ insights/ reports/ dashboards/ my-work/ notifications/
│   │   │   ├── settings/            # Organization settings (rail from config/settings-nav.ts)
│   │   │   ├── account/             # The signed-in user's own account
│   │   │   ├── layout.tsx           # Sidebar, header, providers
│   │   │   └── error.tsx
│   │   ├── (admin-console)/admin/   # Platform admin console
│   │   ├── api/                     # Route handlers: v1/[...path] (API proxy), auth, health, version
│   │   ├── auth/                    # OAuth and SSO callbacks
│   │   ├── invitations/             # Invitation acceptance
│   │   ├── layout.tsx               # Root layout: locale, dir, CSP nonce, providers
│   │   └── error.tsx, not-found.tsx, loading.tsx, globals.css
│   ├── features/<name>/             # Business modules (assets, findings, scans, sensors, ...)
│   │   ├── components/ hooks/ api/ types/ lib/ schemas/ actions/   # as needed
│   │   └── index.ts                 # Barrel export
│   ├── components/                  # Shared components
│   │   ├── ui/                      # shadcn/ui primitives
│   │   ├── layout/                  # Sidebar, header
│   │   └── route-guard.tsx, safe-external-link.tsx, step-up-dialog.tsx, ...
│   ├── config/                      # Sidebar, settings nav, route permissions, legacy redirects
│   ├── context/                     # Providers: tenant, permission, i18n, direction, theme, websocket, ...
│   ├── stores/                      # Zustand (auth-store.ts)
│   ├── lib/                         # Infrastructure
│   │   ├── api/                     # client.ts, endpoints.ts, <area>-hooks.ts, <area>-types.ts,
│   │   │                            # generated/ (contract types, not committed)
│   │   ├── permissions/             # Permission constants, Can, usePermissions
│   │   ├── middleware/              # Proxy helpers: auth, csp, i18n
│   │   ├── i18n/ + i18n.ts          # Dictionaries and translation layer
│   │   └── safe-href.ts, sanitize-markdown.ts, cookies*.ts, utils.ts, ...
│   ├── hooks/                       # Global hooks (use-list-params, use-csv-export, ...)
│   ├── styles/
│   ├── test/                        # Vitest setup
│   └── proxy.ts                     # Next.js 16 proxy: auth redirect, locale, CSP nonce
├── e2e/                             # Playwright tests
├── public/
└── docs/                            # Developer documentation
```

## Folder Responsibilities

### `/app` - Routing Only
**Purpose**: Handle routing, layouts, loading states
**Contains**: `page.tsx`, `layout.tsx`, `loading.tsx`, `error.tsx`, API routes
**Does NOT contain**: Business logic, complex components, data transformations

```tsx
// ✅ Good - Simple, delegates to features
export default async function UsersPage() {
  const users = await getUsers()
  return <UserList users={users} />
}

// ❌ Bad - Too much logic in page
export default function UsersPage() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  // ... complex logic here
}
```

### `/features` - Business Logic
**Purpose**: Contain ALL code related to a specific feature
**Contains**: Components, actions, hooks, schemas, types, utilities for ONE feature
**Rule**: If it's used only by this feature, it goes here

```
features/users/
├── components/     # User-specific UI components
├── actions/        # User CRUD operations (Server Actions)
├── schemas/        # User validation schemas
├── types/          # User-related types
├── hooks/          # User-specific hooks
├── lib/            # User utilities
└── index.ts        # Public API (barrel export)
```

### `/components` - Shared Only
**Purpose**: Components used across MULTIPLE features
**Contains**: UI primitives, layouts, form helpers, providers
**Does NOT contain**: Feature-specific components

```tsx
// ✅ Good - Generic, reusable
components/ui/button.tsx
components/layout/app-header.tsx

// ❌ Bad - Feature-specific
components/user-profile.tsx  // → features/users/components/
components/product-card.tsx  // → features/products/components/
```

### `/lib` - Infrastructure
**Purpose**: Shared infrastructure
**Contains**: The API client and hooks (`lib/api/`), permissions, proxy helpers, i18n, shared helpers. The console has no database: all data comes from the API.
**Does NOT contain**: Business logic, feature-specific code

## Decision Tree: Where Does Code Go?

### For Components:
```
Is it used in ONLY ONE feature?
├── YES → features/[feature]/components/
└── NO → Is it a UI primitive?
    ├── YES → components/ui/
    └── NO → Is it a layout?
        ├── YES → components/layout/
        └── NO → components/ (generic shared)
```

### For Functions/Utilities:
```
Is it used in ONLY ONE feature?
├── YES → features/[feature]/lib/
└── NO → Is it an API call?
    ├── YES → lib/api/
    └── NO → lib/utils.ts or lib/[category].ts
```

### For Types:
```
Is it used in ONLY ONE feature?
├── YES → features/[feature]/types/
└── NO → Is it an API wire type?
    ├── YES → derive from lib/api/generated/api.types.ts (lib/api/<area>-types.ts)
    └── NO → lib/ next to the code that uses it
```

### For Hooks:
```
Is it used in ONLY ONE feature?
├── YES → features/[feature]/hooks/
└── NO → hooks/use-[name].ts
```

## Creating a New Feature

### Step 1: Decide if it's a feature
**Ask:**
- Does it have 2+ related components?
- Does it represent a business domain?
- Could it be deployed independently?

**Examples:**
- ✅ `features/auth/` - Authentication domain
- ✅ `features/users/` - User management
- ✅ `features/products/` - Product catalog
- ❌ `features/button/` - Just UI component
- ❌ `features/utils/` - Just utilities

### Step 2: Create feature structure
```bash
mkdir -p features/[feature-name]/{components,actions,hooks,schemas,types,lib}
touch features/[feature-name]/index.ts
```

### Step 3: Create barrel export
```tsx
// features/[feature-name]/index.ts
export { Component1, Component2 } from "./components/[name]"
export { action1, action2 } from "./actions/[name]-actions"
export { schema } from "./schemas/[name].schema"
export type { Type1, Type2 } from "./types/[name].types"
```

### Step 4: Start building
1. Define types in `types/`
2. Create schemas in `schemas/`
3. Build components in `components/`
4. Add actions in `actions/`
5. Create hooks if needed in `hooks/`

## Feature Dependencies

### Rule: Minimize Feature-to-Feature Dependencies

```tsx
// ❌ Bad - Direct feature dependency
// features/orders/components/order-card.tsx
import { UserAvatar } from "@/features/users/components/user-avatar"

// ✅ Better - Move to shared
// components/ui/avatar.tsx (generic)
// features/orders/components/order-card.tsx
import { Avatar } from "@/components/ui/avatar"

// ✅ Or: Accept as prop
// features/orders/components/order-card.tsx
interface OrderCardProps {
  order: Order
  userAvatar?: ReactNode // Let parent provide
}
```

### Allowed Dependencies:
```
features/[any]/
├── ✅ Can import from: components/
├── ✅ Can import from: lib/
├── ✅ Can import from: hooks/
├── ✅ Can import from: types/
├── ⚠️ Carefully import: other features/ (explicit dependency)
└── ❌ Never import from: app/ (creates circular dependency)
```

## Styling Organization

### CSS Variables
```css
/* app/globals.css */
:root {
  --background: 0 0% 100%;
  --foreground: 222.2 84% 4.9%;
  /* ... theme variables */
}

.dark {
  --background: 222.2 84% 4.9%;
  --foreground: 210 40% 98%;
  /* ... dark theme */
}
```

### Component Styles
```tsx
// ✅ Good - Tailwind utilities
<div className="flex items-center gap-4 p-6 rounded-lg">

// ✅ Good - CSS variables
<div className="bg-background text-foreground">

// ⚠️ OK - Custom CSS when necessary
// styles/custom.css
.custom-gradient {
  background: linear-gradient(...);
}
```

## Import Path Mapping

```json
// tsconfig.json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./*"],
      "@/components/*": ["components/*"],
      "@/features/*": ["features/*"],
      "@/lib/*": ["lib/*"],
      "@/hooks/*": ["hooks/*"],
      "@/types/*": ["types/*"],
      "@/config/*": ["config/*"]
    }
  }
}
```

## Example: a feature module

```
src/features/scans/
├── components/       # Scan list, run detail, dialogs
├── hooks/            # SWR hooks for scans and runs
├── lib/              # Pure helpers (formatting, status mapping)
├── types/            # Feature types
├── __tests__/
└── index.ts          # Public surface of the feature
```

Pages under `src/app/` import from the feature's barrel
(`@/features/scans`) and stay thin; API calls go through `src/lib/api/client.ts`
(see `docs/guides/API_INTEGRATION.md`).

## Key Principles

1. **Colocate by feature** - Keep related code together
2. **Minimize coupling** - Features should be independent
3. **Clear boundaries** - Know what goes where
4. **Consistency** - Same structure for all features
5. **Scalability** - Easy to add new features
6. **Maintainability** - Easy to find and update code

---

**See also:**
- [patterns.md](patterns.md) - Common code patterns
- [troubleshooting.md](troubleshooting.md) - Common issues