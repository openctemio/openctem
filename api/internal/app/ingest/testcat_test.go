package ingest

import "github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"

// testTools hands every organization the built-in tools' catalog.
var testTools = stagetest.Source{Cat: stagetest.Catalog()}
