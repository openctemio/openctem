package extension

// settings hands an extension only the keys it declared.
type settings struct {
	allowed map[string]bool
	getenv  func(string) string
}

func newSettings(keys []string, getenv func(string) string) *settings {
	s := &settings{allowed: make(map[string]bool, len(keys)), getenv: getenv}
	for _, k := range keys {
		s.allowed[k] = true
	}
	return s
}

// Get returns the value of a declared key, and "" for any other key.
func (s *settings) Get(key string) string {
	if !s.allowed[key] {
		return ""
	}
	return s.getenv(key)
}
