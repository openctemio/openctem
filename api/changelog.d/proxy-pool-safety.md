### Behaviour change: An enabled proxy pool must hold a proxy

- The API refuses to create an enabled pool with no proxy, to enable a pool that has none, and to empty the list of an enabled pool (error code `PROXY_POOL_NEEDS_ENDPOINT`, HTTP 400). A sensor on such a pool received no scan jobs, because scans never fall back to a direct connection. Disable the pool first to empty its list. Pools that are already enabled and empty can still be renamed.
- The pool dialog blocks Save in that state with the same message as the default-pool card.
- The sensor's Network path shows an error with Retry (never a false "Inherit") when its data fails to load, a skeleton while loading, asks before going Direct while the organization default is on, and marks disabled pools.
- Delete is disabled with a reason while sensors use a pool; "1 sensor assigned" is singular; on-screen changes no longer toast; the pool strategy and network path use the shared select.
