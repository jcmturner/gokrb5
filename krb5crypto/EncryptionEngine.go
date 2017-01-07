package krb5crypto

type encryptFunc func([]byte, []byte) []byte

func deriveRandom(key, usage []byte, n, k int, encrypt encryptFunc) {
	nFoldUsage := Nfold(usage, n)
	out := make([]byte, k / 8)

	fillBytes := encrypt(nFoldUsage, key)
	p := 0
	for i := 0; i < len(out); i++ {
		if p < len(fillBytes) {
			out[i] = fillBytes[p]
			p += 1
		} else {
			fillBytes = encrypt(nFoldUsage, key)
			p = 0
			out[i] = fillBytes[p]
			p += 1
		}
	}
	return out
}

