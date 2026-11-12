package pairing

// EncodeCodeForTest exposes encodeCode to the vector test.
func EncodeCodeForTest(b [5]byte) string { return encodeCode(b) }
