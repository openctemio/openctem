// Command openapidiff reports what a change does to the API contract.
//
// The contract files are generated, not committed (`make contract`), so a pull
// request's diff no longer shows its API changes. Web CI generates the files for
// the base and for the head and runs this to put the difference in front of the
// reviewer, as the job summary and a pull request comment:
//
//   - operations added or removed, a parameter that became required, a request
//     or response body whose schema changed;
//   - definition (request/response type) changes, via tools/lint/openapischema;
//   - route gate changes in the web console's route permission map;
//   - registered routes added or removed (api/openapi/routes.txt).
//
// It reports and never fails: a breaking change can be intended. Reviewers
// decide; the report makes sure they see it.
//
// Usage:
//
//	openapidiff -base DIR -head DIR [-base-label X] [-head-label Y] > report.md
//
// Each DIR holds swagger.yaml, routes.txt and api-route-permissions.json; a
// missing file counts as empty.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	base := flag.String("base", "", "directory with the base contract files")
	head := flag.String("head", "", "directory with the head contract files")
	baseLabel := flag.String("base-label", "base", "label for the base (e.g. a short sha)")
	headLabel := flag.String("head-label", "head", "label for the head")
	flag.Parse()
	if *base == "" || *head == "" {
		fmt.Fprintln(os.Stderr, "usage: openapidiff -base DIR -head DIR")
		os.Exit(2)
	}
	b, err := loadBundle(*base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openapidiff: base:", err)
		os.Exit(2)
	}
	h, err := loadBundle(*head)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openapidiff: head:", err)
		os.Exit(2)
	}
	fmt.Print(render(compare(b, h), *baseLabel, *headLabel))
}
