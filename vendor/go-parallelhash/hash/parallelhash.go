// Package hash provides implementations of standard cryptographic hash functions
// as well as the ParallelHash functions defined in NIST SP 800-185.
package hash

import (
	"golang.org/x/crypto/sha3"
	"sync"
)

// --- NIST SP 800-185 Helper Functions ---

// bytepad pads the input X according to the NIST SP 800-185 standard.
// It prepends the encoded rate w to X and then appends zero bytes until the
// result is a multiple of w.
func bytepad(X []byte, w int) []byte {
	// left_encode(w) || X
	z := append(leftEncode(w), X...)
	// Pad with zeros until a multiple of w.
	for len(z)%w != 0 {
		z = append(z, 0x00)
	}
	return z
}

// encodeString encodes a byte string S as specified in NIST SP 800-185.
// The encoding is defined as left_encode(len(S) in bits) || S.
func encodeString(S []byte) []byte {
	bitLen := len(S) * 8
	return append(leftEncode(bitLen), S...)
}

// leftEncode encodes an integer x by prefixing it with its byte-length.
// This is used for creating domain separation in NIST hash function constructions.
func leftEncode(x int) []byte {
	// Determine the number of bytes required to represent x.
	n := 1
	for (1 << (8 * n)) <= x {
		n++
	}
	result := make([]byte, n+1)
	result[0] = byte(n) // The first byte is the length of the encoding.
	for i := 0; i < n; i++ {
		result[n-i] = byte(x >> (8 * i))
	}
	return result
}

// rightEncode encodes an integer x by suffixing it with its byte-length.
func rightEncode(x int) []byte {
	// Determine the number of bytes required to represent x.
	n := 1
	for (1 << (8 * n)) <= x {
		n++
	}
	result := make([]byte, n+1)
	for i := 0; i < n; i++ {
		result[i] = byte(x >> (8 * (n - 1 - i)))
	}
	result[n] = byte(n) // The last byte is the length of the encoding.
	return result
}

// --- cSHAKE Implementations ---

// cSHAKE128 is a customizable variant of SHAKE128, as defined in NIST SP 800-185.
// It allows for a function name (N) and a customization string (S) to create
// different hash function variants from the same base.
// L is the desired output length in bits.
func cSHAKE128(X []byte, L int, N, S string) []byte {
	// If both N and S are empty, cSHAKE is equivalent to SHAKE.
	if N == "" && S == "" {
		out := make([]byte, L/8)
		sha3.ShakeSum128(out, X)
		return out
	}

	// cSHAKE128 has a rate of 168 bytes (1344 bits).
	const rate = 168
	prefix := bytepad(append(encodeString([]byte(N)), encodeString([]byte(S))...), rate)

	// The input to the underlying SHAKE function is the prefix followed by the message.
	// A domain separation suffix of 0x04 is used for cSHAKE.
	input := append(prefix, X...)
	input = append(input, 0x04)

	out := make([]byte, L/8)
	shake := sha3.NewShake128()
	shake.Write(input)
	shake.Read(out)
	return out
}

// cSHAKE256 is a customizable variant of SHAKE256.
// L is the desired output length in bits.
func cSHAKE256(X []byte, L int, N, S string) []byte {
	// If both N and S are empty, cSHAKE is equivalent to SHAKE.
	if N == "" && S == "" {
		out := make([]byte, L/8)
		sha3.ShakeSum256(out, X)
		return out
	}

	// cSHAKE256 has a rate of 136 bytes (1088 bits).
	const rate = 136
	prefix := bytepad(append(encodeString([]byte(N)), encodeString([]byte(S))...), rate)

	input := append(prefix, X...)
	input = append(input, 0x04) // Domain separation for cSHAKE

	out := make([]byte, L/8)
	shake := sha3.NewShake256()
	shake.Write(input)
	shake.Read(out)
	return out
}

// --- ParallelHash Implementations ---

// ParallelHash128Goroutines implements the NIST SP 800-185 ParallelHash128
// function using one goroutine per data block for parallel processing.
//
// Parameters:
//   X: The input message.
//   B: The block size in bytes for parallel processing.
//   L: The desired output length in bits.
//   S: A customization string.
func ParallelHash128Goroutines(X []byte, B int, L int, S string) []byte {
	// The underlying hash function for intermediate blocks is a plain SHAKE128,
	// which is equivalent to cSHAKE128 with empty N and S strings.
	// The output length of each intermediate hash is 256 bits.
	cshakeFunc := func(data []byte) []byte {
		return cSHAKE128(data, 256, "", "")
	}

	// The final hash uses the full cSHAKE128 with N="ParallelHash".
	finalCshakeFunc := func(data []byte) []byte {
		return cSHAKE128(data, L, "ParallelHash", S)
	}

	return parallelHashGoroutines(X, B, L, cshakeFunc, finalCshakeFunc)
}

// ParallelHash256Goroutines implements the NIST SP 800-185 ParallelHash256
// function using one goroutine per data block.
func ParallelHash256Goroutines(X []byte, B int, L int, S string) []byte {
	// Use cSHAKE256 for both intermediate and final hashing steps.
	cshakeFunc := func(data []byte) []byte {
		return cSHAKE256(data, 512, "", "") // Intermediate hashes are 512 bits.
	}
	finalCshakeFunc := func(data []byte) []byte {
		return cSHAKE256(data, L, "ParallelHash", S)
	}
	return parallelHashGoroutines(X, B, L, cshakeFunc, finalCshakeFunc)
}

// parallelHashGoroutines provides the generic, parallelized implementation of ParallelHash.
// It is unexported and used by the public-facing ParallelHash functions.
// It accepts the hashing functions as parameters to avoid code duplication.
func parallelHashGoroutines(X []byte, B int, L int, intermediateHash, finalHash func([]byte) []byte) []byte {
	// Calculate the number of blocks, rounding up.
	blockCount := (len(X) + B - 1) / B
	if blockCount == 0 { // Handle empty input case.
		blockCount = 1
	}

	// Pre-allocate a slice to hold the intermediate hash results.
	intermediates := make([][]byte, blockCount)
	var wg sync.WaitGroup

	// Process each block in a separate goroutine.
	for i := 0; i < blockCount; i++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()

			start := blockIndex * B
			end := start + B
			if end > len(X) {
				end = len(X)
			}
			block := X[start:end]

			// Compute the hash of the block and store it.
			intermediates[blockIndex] = intermediateHash(block)
		}(i)
	}

	// Wait for all block hashing goroutines to complete.
	wg.Wait()

	// Concatenate the results: left_encode(B) || h_1 || h_2 || ... || h_n
	var z []byte
	z = append(z, leftEncode(B)...)
	for _, h := range intermediates {
		z = append(z, h...)
	}

	// Append the final encoded elements: right_encode(blockCount) || right_encode(L)
	z = append(z, rightEncode(blockCount)...)
	z = append(z, rightEncode(L)...)

	// Compute and return the final hash.
	return finalHash(z)
}
