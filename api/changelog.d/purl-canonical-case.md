### Fixed: one spelling for a package across the inventory and its findings

- The software inventory now lower-cases the namespace and name of `alpm`, `apk`, `deb` and `hex` package URLs, as finding identity already did. A report spelling `pkg:deb/Debian/OpenSSL` no longer creates a package apart from `pkg:deb/debian/openssl`, which its findings were keyed on. Packages already stored with upper-case letters stay as they are; the next report links the lower-case package.
