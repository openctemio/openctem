### Fixed: a path exclusion no longer refuses POST and other methods on the whole host

A web job whose scope only denies paths now lists every HTTP method. The sensor read an empty method list as GET, HEAD and OPTIONS only, so a single path exclusion refused every POST, PUT, PATCH and DELETE request on every path of its hosts. nuclei counted those refusals as host errors and skipped the hosts as unresponsive (`breaker_open`). A rule that blocks only some methods still limits the job to GET and HEAD.
