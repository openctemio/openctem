package aianalysis

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

//go:embed prompts/*.txt
var promptFS embed.FS

// PromptTemplate is the system prompt of a single-shot kind with the digest
// recorded on every run (so a result names exactly the template it came from).
type PromptTemplate struct {
	ID     string
	Text   string
	Digest string
}

// TemplateFor returns the built-in template of a kind: the shared data and
// output rules followed by the kind's task and format.
func TemplateFor(kind string) (PromptTemplate, error) {
	common, err := promptFS.ReadFile("prompts/common.txt")
	if err != nil {
		return PromptTemplate{}, fmt.Errorf("read prompt: %w", err)
	}
	task, err := promptFS.ReadFile("prompts/" + kind + ".txt")
	if err != nil {
		return PromptTemplate{}, fmt.Errorf("%w: no built-in template for this kind", shared.ErrValidation)
	}
	text := string(common) + "\n" + string(task)
	sum := sha256.Sum256([]byte(text))
	return PromptTemplate{ID: kind, Text: text, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
