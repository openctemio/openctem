## Summary

<!-- What does this change and why? -->

## Checklist

- [ ] Tests or a manual check show the change works.
- [ ] Every commit author has accepted the OpenCTEM [Contributor License Agreement](https://docs.openctem.io/legal/cla/) (the `cla` check tells you how), or is a maintainer.

## Paid feature?

Delete this section when the change adds or moves no paid (Enterprise) feature.
Paid-feature code is written only in the private overlay repository; this repository gets generic extension points and entitlement keys.

- [ ] The entitlement key is registered in `api/pkg/domain/limits` with a description (`entitlement_keys_test.go` passes).
- [ ] The feature is gated through the entitlement service, never by plan, tier, edition or brand name.
- [ ] Community behaviour is unchanged: the default build runs without the overlay and nothing was removed from it.
- [ ] The docs page carries the Enterprise badge, and no commercial brand name or plan wording is in code, docs or UI text.
