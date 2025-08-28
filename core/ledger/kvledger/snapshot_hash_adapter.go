package kvledger

import (
	"bytes"
	"go-parallelhash/hash"
)

// ParallelHashAdapter implements the standard hash.Hash interface to wrap our
// non-streaming ParallelHash function.
type ParallelHashAdapter struct {
	buffer bytes.Buffer
	L      int    // Output length in bits
	B      int    // Block size
	S      string // Customization string
}

// Write appends data to an internal buffer. It is part of the hash.Hash interface.
func (a *ParallelHashAdapter) Write(p []byte) (n int, err error) {
	return a.buffer.Write(p)
}

// Sum calculates the ParallelHash of the entire buffer and returns the result.
// It is part of the hash.Hash interface.
func (a *ParallelHashAdapter) Sum(b []byte) []byte {
	// Call your actual ParallelHash function on the buffered data.
	// We are using ParallelHash256 which has a 512-bit output by default.
	// L and B can be made configurable later if needed.
	result := hash.ParallelHash256Goroutines(a.buffer.Bytes(), a.B, a.L, a.S)
	return append(b, result...)
}

// Reset clears the buffer for the next use. It is part of the hash.Hash interface.
func (a *ParallelHashAdapter) Reset() {
	a.buffer.Reset()
}

// Size returns the output size in bytes. It is part of the hash.Hash interface.
func (a *ParallelHashAdapter) Size() int {
	return a.L / 8
}

// BlockSize can return 1 for a streaming hash. It is part of the hash.Hash interface.
func (a *ParallelHashAdapter) BlockSize() int {
	return 1
}
