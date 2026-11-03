// Package extension is the public, versioned back-end extension API of
// OpenCTEM (docs/development/extension-api.md).
//
// Anyone can build their own edition of the platform by writing an extension
// package against this API and compiling it into the server. An extension
// registers itself once, from an init function, with Register; the build
// switch (cmd/server/edition_ee.go, behind a build tag) is the only core file
// that imports an extension package. The Community build registers nothing
// and runs with the core defaults.
//
// What an extension gets is listed in Deps, and every field there is an
// interface or a public type: the core hands out no database pool, no
// configuration struct and no internal service. What an extension can add is
// listed in Extension:
//
//   - a grant provider (Grants): things that are off unless granted;
//   - background controllers (Controllers), run by the core controller
//     manager, on one replica when the controller is Exclusive;
//   - HTTP routes (Routes) under /api/v1, each with a mandatory core
//     permission and a mandatory grant key; the core mounts them behind its
//     authentication, organization, permission and grant checks;
//   - database migrations (Migrations) in the extension's own schema
//     (Schema), never in the core schema;
//   - the configuration keys it reads (ConfigKeys), handed out through
//     Settings; any other key reads as empty.
//
// Tests of an extension get the Deps the core would hand it, built by the
// core's own implementations on a test database, from package
// extensiontest.
//
// An audit sink is a controller that reads the administrators' audit chain
// through Deps.AdminAudit and keeps its position with the forward cursor.
//
// # Versioning
//
// APIVersion is the version of this contract. An extension states the
// version it was written for as a literal in Extension.APIVersion, and
// Register panics on a mismatch, so a build against an incompatible core
// fails at its first start (and in its tests). Adding an optional field or a
// new interface is not a break. Removing or renaming a field, a method or a
// type, or narrowing a type, is, and bumps APIVersion. The exported surface
// is recorded in testdata/api.golden and a test fails when it changes
// without that file (and, for a removal, the version) being updated.
// Changes go expand, then migrate the extensions, then contract: the old
// form stays for at least one release train.
package extension
