### Changed: discovered services, certificates and web endpoints follow their host

- A service, certificate or web endpoint that discovery left waiting for
  review is now linked to the host it was seen on (by a stored relationship
  of the organization, or by the host in its own name) and carries the
  host's state. Confirming, rejecting or scoping the host decides its
  children too; a person can still decide a child on its own, which ends
  the link.
- The Attack surface review queue lists the host only, with how many
  services, certificates and web endpoints follow it; its count no longer
  counts children.
- Upgrade note: migration `attribution_children_follow_host` adds a nullable
  column and links existing pending children of pending hosts by stored
  relationship. It changes no state and is safe on populated tables.
