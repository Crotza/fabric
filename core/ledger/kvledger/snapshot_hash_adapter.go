package kvledger

import (
	"bytes"
	"go-parallelhash/hash"
	"runtime"
)

// ParallelHashAdapter implements the standard hash.Hash interface to wrap our
// non-streaming ParallelHash function.
type ParallelHashAdapter struct {
	buffer bytes.Buffer
	L      int    // Output length in bits
	S      string // Customization string
}

// Write appends data to an internal buffer. It is part of the hash.Hash interface.
func (a *ParallelHashAdapter) Write(p []byte) (n int, err error) {
	return a.buffer.Write(p)
}

// Sum calculates the ParallelHash of the entire buffer and returns the result.
func (a *ParallelHashAdapter) Sum(b []byte) []byte {
    // Get the number of available CPU cores.
    numCPU := runtime.NumCPU()
    if numCPU == 0 {
        numCPU = 1 // Avoid division by zero on unusual systems.
    }

    // Get the total size of the data in the buffer.
    totalSize := a.buffer.Len()
    if totalSize == 0 {
        // Handle empty input gracefully.
        return hash.ParallelHash256Goroutines(a.buffer.Bytes(), 1, a.L, a.S)
    }

    // Calculate the optimal block size.
    optimalBlockSize := totalSize / numCPU
    
    // Set a minimum block size to avoid creating too many tiny blocks, which can hurt performance.
    const minBlockSize = 1024 * 64 // 64KB
    if optimalBlockSize < minBlockSize {
        optimalBlockSize = minBlockSize
    }
    
    // 6. Call your hash function with the new dynamic block size.
    result := hash.ParallelHash256Goroutines(a.buffer.Bytes(), optimalBlockSize, a.L, a.S)
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
