### Fixed: a path exclusion with a `*` segment no longer blocks a whole origin on sensors that read it

- A web job's scope now keeps the deny paths as written beside the cut form. A sensor that reads `*` segments (v0.38.2 and v0.37.2 or later, contract webpath 1.3.1) is sent the written form, so `/tenants/*/admin` denies the admin path of every tenant and nothing else; an older, unknown or shared sensor still gets the cut form (`/tenants/`), which over-blocks but never lets the path through. The platform-only key is removed before a job is signed or handed out.
