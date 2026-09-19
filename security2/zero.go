package security2

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
