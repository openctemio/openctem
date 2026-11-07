package contentpack

import (
	"fmt"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/templatefact"
)

// lintTemplateFacts validates a template facts file
// (docs/architecture/template-facts.md): every entry valid, entry ids
// unique in the pack. Other files are data.
func lintTemplateFacts(rep *dom.LintReport, f dom.File, ids map[string]string) {
	if !isYAML(f.Path) {
		return
	}
	entries, err := templatefact.ParseFile(f.Data)
	if err != nil {
		rep.Error(f.Path, "INVALID_TEMPLATE_FACTS", err.Error())
		return
	}
	for i := range entries {
		id := entries[i].ID
		if prev, dup := ids[id]; dup {
			rep.Error(f.Path, "DUPLICATE_ENTRY", fmt.Sprintf("entry id %s is also in %s", id, prev))
			continue
		}
		ids[id] = f.Path
		rep.Items++
	}
}
