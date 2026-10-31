package contentpack

import (
	"fmt"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
)

// lintRules checks one file of a detection rule pack
// (docs/architecture/rule-packs.md): every YAML file is a rules file whose
// rules must all validate for the pack's kind, and a rule id is unique in
// the pack. Other files (NOTICE, README) are not rules. Rules are data: they
// fetch and send nothing, so a rule pack is always T0.
func lintRules(rep *dom.LintReport, f dom.File, kind string, ids map[string]string) {
	if !isYAML(f.Path) {
		return
	}
	rules, err := contentrule.ParseFile(f.Data)
	if err != nil {
		rep.Error(f.Path, "INVALID_RULES", err.Error())
		return
	}
	for i := range rules {
		r := &rules[i]
		if err := r.Validate(contentrule.Kind(kind)); err != nil {
			rep.Error(f.Path, "INVALID_RULE", fmt.Sprintf("rule %d (%s): %v", i+1, r.ID, err))
			continue
		}
		if prev, dup := ids[r.ID]; dup {
			rep.Error(f.Path, "DUPLICATE_RULE", fmt.Sprintf("rule id %s is also in %s", r.ID, prev))
			continue
		}
		ids[r.ID] = f.Path
		rep.Items++
	}
}
