### Security: scope coverage counts only the assets the caller may see

- `GET /api/v1/scope/stats` computed "inventory in scope" over every asset of
  the organization for any holder of `attack_surface:scope:read`, so a
  restricted member learned the size of the inventory outside their data
  scope. It also paged every asset into memory on each page load. The counts
  are now one SQL query over the caller's data scope (a member with no scope
  rows counts nothing), and a data scope that cannot be resolved fails the
  request instead of falling back to tenant-wide numbers.

### Changed: "Inventory in scope" means the internet-facing inventory

- `coverage` is now the share of the internet-facing inventory (domains,
  subdomains, public addresses, services and applications whose attribution
  puts them in the inventory) that an active scope target covers and no
  exclusion removes. Repositories, cloud resources, review-queue items and
  rejected names no longer dilute it; internal names and private addresses
  are counted apart. A URL or `host:port` asset is matched on its host, as
  the active-probe authority does.
- New response fields `inventory_internet_facing`, `inventory_in_scope` and
  `inventory_internal`.
