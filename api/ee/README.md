# api/ee

Empty in this repository on purpose. A build that adds a private overlay
compiles it into this directory; nothing here is ever tracked, and CI fails
when a file other than this README is. The Community build never imports from
here. Paid-feature code is written only in the private overlay repository; this
repository gets generic extension points and entitlement keys. See
[editions](../docs/development/editions.md).
