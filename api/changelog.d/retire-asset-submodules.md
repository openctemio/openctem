### Removed: per-type asset sub-modules

- The `assets.*` sub-modules (Domains, IP Addresses, Repositories, ...)
  are removed from the module catalogue and from tenant module settings.
  They gated the per-type asset pages, which are now views of the one
  inventory; switching one off no longer did anything. The inventory as a
  whole stays gated by the `assets` module. A migration deletes the rows
  and any tenant override of them; the down migration is a no-op.
