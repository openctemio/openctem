package licensekey

// The license roots this build trusts: standard base64 of raw 32-byte
// Ed25519 public keys, the current root and a pre-staged next root, so a
// root rotation is one release away. The private halves are held offline
// and sign only key sets. There is deliberately no environment variable,
// flag or setting that adds a root: changing trust needs a rebuilt core.
//
// Empty until the root key ceremony: a build without a root verifies no
// license and runs as Community (every Community feature, no grants).
// roots_test.go checks every entry and that the test root is never listed.
var embeddedRoots = []string{}

// embeddedMinKeySetVersion is the lowest key-set version this build accepts;
// a release raises it to retire key sets (and the keys they list).
const embeddedMinKeySetVersion uint64 = 1

// embeddedRevoked are revocations shipped with this build (leaked license
// files, retired issuing keys).
var embeddedRevoked = Revocations{}
