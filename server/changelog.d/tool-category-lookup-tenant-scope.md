### Security: tool lookups by category are tenant-scoped
- Checking whether a tool category is in use (when a tenant deletes a custom category) only counts platform tools and the caller's own tools, never another tenant's.
- Removed the unused list-tools-by-category-name lookup, which had no tenant filter.
