// Package findinglifecycle holds an organization's lifecycle layer on top of
// the canonical finding statuses (docs/rfcs/RFC-110-tenant-lifecycles.md):
// sub-statuses, each bound for ever to one canonical status (and, under a
// closed status, to one closure reason), and lifecycle schemes that may only
// add constraints to the platform's transition engine.
package findinglifecycle
