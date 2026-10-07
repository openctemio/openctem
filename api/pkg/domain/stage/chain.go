package stage

// Feeds reports whether pred's outputs can be next's inputs: at least one
// type pred produces is a type next accepts. A stage that only reports
// findings feeds nothing.
func Feeds(pred, next Stage) bool {
	for _, out := range pred.Outputs {
		if next.Accepts(out) {
			return true
		}
	}
	return false
}
