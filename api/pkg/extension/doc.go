// Package extension is the public, versioned back-end extension API of
// OpenCTEM (docs/development/editions.md).
//
// Anyone can build their own edition of the platform: a separate Go module
// requires github.com/openctemio/openctem/api, writes one or more extensions
// against this package, and calls server.Main (api/pkg/server) from its own
// main with them:
//
//	func main() { server.Main(myext.Extension(), partner.Extension()) }
//
// Go's internal rule then lets the build use only the public api/pkg
// packages. The Community build passes no extension and runs with the core
// defaults. An Extension is plain data plus constructors, so the core never
// depends on how an extension got into the process.
//
// What an extension gets is listed in Deps, and every field there is an
// interface or a public type: the core hands out no database pool, no
// configuration struct and no internal service. What an extension can add is
// listed in Extension:
//
//   - a grant provider (Grants): things that are off unless granted; at most
//     one per build;
//   - background controllers (Controllers), run by the core controller
//     manager, on one replica when the controller is Exclusive;
//   - HTTP routes (Routes) under /api/v1, each with a mandatory core
//     permission and a mandatory grant key; the core mounts them behind its
//     authentication, organization, permission and grant checks;
//   - database migrations (Migrations) in the extension's own schema
//     (Schema), never in the core schema;
//   - the configuration keys it reads (ConfigKeys), handed out through
//     Settings; any other key reads as empty, and core keys are refused.
//
// Names, schemas and config keys are unique across a build's extensions;
// the server checks the whole build (ValidateBuild) before anything starts
// and refuses to start on a mistake.
//
// Tests of an extension get the Deps the core would hand it, built by the
// core's own implementations on a test database, from package
// extensiontest.
//
// # Versioning
//
// APIVersion is the version of this contract and stays 1 until the core's
// 1.0 release. An extension states the version it was written for as a
// literal in Extension.APIVersion and the server refuses to start on a
// mismatch. Before 1.0 a breaking change goes expand (the new form is
// added, the old kept), then migrate the extensions, then contract (the old
// form removed) within one release train, and is listed under "Extension
// API" in the release notes. The exported surface is recorded in
// testdata/api.golden; a test fails when it changes without that file being
// updated.
package extension
