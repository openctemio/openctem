package postgres

import "fmt"

// maxBindParams is the most bind parameters PostgreSQL accepts in one
// statement (the wire protocol counts them in an unsigned 16-bit field). A
// statement over it is refused as a whole.
const maxBindParams = 65535

// rowsPerStatement is how many rows of paramsPerRow parameters fit in one
// statement next to fixedParams parameters shared by the whole statement.
// limit > 0 caps it lower (smaller statements for very wide inputs); a limit
// above what fits is ignored, so a chunk constant can never exceed the
// protocol limit again.
func rowsPerStatement(paramsPerRow, fixedParams, limit int) int {
	if paramsPerRow <= 0 {
		paramsPerRow = 1
	}
	n := (maxBindParams - fixedParams) / paramsPerRow
	if limit > 0 && limit < n {
		n = limit
	}
	if n < 1 {
		n = 1
	}
	return n
}

// forEachStatementChunk calls fn with consecutive [start, end) ranges over
// total rows, each small enough for one statement (see rowsPerStatement). The
// first error stops the loop and is returned with the failing range, so a
// partial write is never reported as success.
func forEachStatementChunk(total, paramsPerRow, fixedParams, limit int, fn func(start, end int) error) error {
	size := rowsPerStatement(paramsPerRow, fixedParams, limit)
	for start := 0; start < total; start += size {
		end := min(start+size, total)
		if err := fn(start, end); err != nil {
			return fmt.Errorf("rows %d-%d of %d: %w", start, end, total, err)
		}
	}
	return nil
}
