### Fixed: the module state cache and its ETag follow every change of the effective state

- A read-only grace or a timed deny that ends by itself is no longer served from a stale cache or a stale `304`: the cache entry ends at that moment, and the ETag of the modules endpoints includes a hash of the effective state.
- An entitlement that could not be read (every module reported unavailable, fail closed) is answered for that request only. It is no longer kept for a few seconds, and the console no longer keeps the "everything off" payload through `304` after the reader recovers.
- A Redis flush or eviction no longer resets the module version to a value an old ETag can match, and a toggle racing a cache read can no longer leave the old state cached.
- The threat-alert planner reads the same module cache as the routes, so entitlement and module changes reach it at once.
