package scanrun

import (
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"
)

// testCat is the catalog of an organization whose sensors report the
// built-in tools' contracts and one for zap (dast.web, T2).
var testCat = stagetest.Catalog(stage.ToolFacts{Name: "zap", Implements: []stage.Key{stage.DASTWeb}})

// testTools hands testCat to every organization.
var testTools = stagetest.Source{Cat: testCat}
