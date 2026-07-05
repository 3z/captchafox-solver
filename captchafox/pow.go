package captchafox

import (
	"crypto/sha256"
	"strconv"
)

// SolvePow finds the smallest nonce whose sha256(seed+nonce) hex digest
// starts with `difficulty` leading '0' characters. This is the CaptchaFox
// proof-of-work: the worker message is [tag, seed, difficultyBinaryString]
// where the difficulty is the count of leading hex zeros (parsed from a
// binary string such as "101" -> 5). The seed and nonce are concatenated as
// decimal-integer strings, exactly mirroring the Python reference:
// hashlib.sha256(f"{seed}{nonce}".encode("utf-8")).hexdigest().
func SolvePow(seed string, difficulty int) int {
	// N leading hex zeros == N/2 leading zero bytes plus, when N is odd, one
	// extra byte whose high nibble is zero (< 0x10). Checking raw digest bytes
	// avoids allocating a hex string on every iteration.
	fullZeroBytes := difficulty / 2
	needHalfZero := difficulty%2 == 1

	// Reusable buffer: seed bytes followed by the nonce digits. The nonce is a
	// non-negative integer so its decimal form is at most 20 characters.
	buf := make([]byte, len(seed), len(seed)+20)
	copy(buf, seed)

	nonce := 0
	for {
		nstr := strconv.Itoa(nonce)
		msg := append(buf[:len(seed)], nstr...)
		sum := sha256.Sum256(msg)

		ok := true
		for i := 0; i < fullZeroBytes; i++ {
			if sum[i] != 0 {
				ok = false
				break
			}
		}
		if ok && needHalfZero && sum[fullZeroBytes] >= 0x10 {
			ok = false
		}
		if ok {
			return nonce
		}
		nonce++
	}
}
