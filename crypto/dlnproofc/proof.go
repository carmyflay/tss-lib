package dlnproofc

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

const Iterations = 128 // Match the C wrapper's ITERATIONS

type Proof struct {
	Alpha [Iterations]*big.Int
	T     [Iterations]*big.Int
}

// var one = big.NewInt(1)

// NewDLNProof generates a new DLN proof using the C implementation
func NewDLNProof(h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	// Convert big.Int to byte slices for C wrapper
	h1Bytes := h1.Bytes()
	xBytes := x.Bytes()
	pBytes := p.Bytes()
	qBytes := q.Bytes()
	NBytes := N.Bytes()

	// Generate a hash for the proof (using h1 and h2)
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2.Bytes())
	hash := hasher.Sum(nil)

	// Determine output length (use the largest input size)
	outLen := len(NBytes)
	if len(h1Bytes) > outLen {
		outLen = len(h1Bytes)
	}
	if len(xBytes) > outLen {
		outLen = len(xBytes)
	}

	// Call the C wrapper to generate proof
	alphaList, tList, err := DLNProve(h1Bytes, xBytes, pBytes, qBytes, NBytes, hash, outLen)
	if err != nil {
		// Return nil on error - in production you might want to handle this differently
		return nil
	}

	// Convert byte slices back to big.Int
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = new(big.Int).SetBytes(alphaList[i])
		proof.T[i] = new(big.Int).SetBytes(tList[i])
	}

	return proof
}

// Verify checks if the DLN proof is valid using the C implementation
func (p *Proof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}

	// Convert big.Int to byte slices
	h1Bytes := h1.Bytes()
	h2Bytes := h2.Bytes()
	NBytes := N.Bytes()

	// Generate the same hash used during proof generation
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2Bytes)
	hash := hasher.Sum(nil)

	// Convert proof arrays to byte slice arrays
	alphaList := make([][]byte, Iterations)
	tList := make([][]byte, Iterations)
	for tL := range tList {
		fmt.Printf("%d \n", len(tList[tL]))
	}
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		alphaList[i] = p.Alpha[i].Bytes()
		tList[i] = p.T[i].Bytes()
	}

	// Call the C wrapper to verify proof
	valid, err := DLNVerify(h1Bytes, h2Bytes, NBytes, alphaList, tList, hash)
	if err != nil {
		fmt.Println("DLNVerify error:", err)
		return false
	}

	return valid
}

// Helper function to pad byte slices to ensure consistent length
func padBytes(data []byte, length int) []byte {
	if len(data) >= length {
		return data
	}

	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}

// NewDLNProofWithPadding generates a proof with consistent byte lengths
func NewDLNProofWithPadding(h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	// Calculate the maximum byte length needed
	maxLen := 0
	inputs := []*big.Int{h1, h2, x, p, q, N}
	for _, input := range inputs {
		if l := len(input.Bytes()); l > maxLen {
			maxLen = l
		}
	}

	// Pad all inputs to the same length
	h1Bytes := padBytes(h1.Bytes(), maxLen)
	xBytes := padBytes(x.Bytes(), maxLen)
	pBytes := padBytes(p.Bytes(), maxLen)
	qBytes := padBytes(q.Bytes(), maxLen)
	NBytes := padBytes(N.Bytes(), maxLen)

	// Generate hash
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2.Bytes())
	hash := hasher.Sum(nil)

	// Call C wrapper
	alphaList, tList, err := DLNProve(h1Bytes, xBytes, pBytes, qBytes, NBytes, hash, maxLen)
	if err != nil {
		return nil
	}

	// Convert to big.Int
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = new(big.Int).SetBytes(alphaList[i])
		proof.T[i] = new(big.Int).SetBytes(tList[i])
	}

	return proof
}

// VerifyWithPadding verifies a proof with consistent byte lengths
func (p *Proof) VerifyWithPadding(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}

	// Calculate maximum length
	maxLen := 0
	inputs := []*big.Int{h1, h2, N}
	for _, input := range inputs {
		if l := len(input.Bytes()); l > maxLen {
			maxLen = l
		}
	}

	// Also check proof elements for maximum length
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] != nil {
			if l := len(p.Alpha[i].Bytes()); l > maxLen {
				maxLen = l
			}
		}
		if p.T[i] != nil {
			if l := len(p.T[i].Bytes()); l > maxLen {
				maxLen = l
			}
		}
	}

	// Pad inputs
	h1Bytes := padBytes(h1.Bytes(), maxLen)
	h2Bytes := padBytes(h2.Bytes(), maxLen)
	NBytes := padBytes(N.Bytes(), maxLen)

	// Generate hash
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2Bytes)
	hash := hasher.Sum(nil)

	// Convert proof to padded byte arrays
	alphaList := make([][]byte, Iterations)
	tList := make([][]byte, Iterations)

	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		alphaList[i] = padBytes(p.Alpha[i].Bytes(), maxLen)
		tList[i] = padBytes(p.T[i].Bytes(), maxLen)
	}

	// Call C wrapper
	valid, err := DLNVerify(h1Bytes, h2Bytes, NBytes, alphaList, tList, hash)
	if err != nil {
		return false
	}

	return valid
}
