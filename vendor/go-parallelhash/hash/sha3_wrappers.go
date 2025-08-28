// Package hash provides implementations of standard cryptographic hash functions
// as well as the ParallelHash functions defined in NIST SP 800-185.
package hash

import (
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
)

// SHA256Hash computes the SHA-256 hash of the input data.
// This is a simple wrapper around the crypto/sha256 package.
func SHA256Hash(data []byte) []byte {
	// sha256.Sum256 is a more direct and efficient way to compute the hash.
	hash := sha256.Sum256(data)
	return hash[:] // Return a slice of the full array.
}

// SHA3256Hash computes the SHA3-256 hash of the input data.
// It returns a 32-byte (256-bit) hash.
func SHA3256Hash(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}

// SHA3512Hash computes the SHA3-512 hash of the input data.
// It returns a 64-byte (512-bit) hash.
func SHA3512Hash(data []byte) []byte {
	hash := sha3.Sum512(data)
	return hash[:]
}

// SHAKE128Hash computes a hash using the SHAKE128 extendable-output function (XOF).
// It reads 'outLenBits' from the SHAKE stream and returns them as a byte slice.
func SHAKE128Hash(data []byte, outLenBits int) []byte {
	out := make([]byte, outLenBits/8)
	// sha3.ShakeSum128 is a helper function that computes the hash in one call.
	sha3.ShakeSum128(out, data)
	return out
}

// SHAKE256Hash computes a hash using the SHAKE256 extendable-output function (XOF).
// It reads 'outLenBits' from the SHAKE stream and returns them as a byte slice.
func SHAKE256Hash(data []byte, outLenBits int) []byte {
	out := make([]byte, outLenBits/8)
	sha3.ShakeSum256(out, data)
	return out
}
