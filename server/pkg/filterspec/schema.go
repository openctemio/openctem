package filterspec

import _ "embed"

// DocumentSchema is the JSON Schema of the FilterDocument (RFC-048 §3.6).
// The parser is the authority; the schema documents the shape for clients,
// saved-view editors and MCP tool definitions.
//
//go:embed filter_document.schema.json
var DocumentSchema []byte
