package dlnproofc

// import (
// 	"crypto/rand"
// 	"crypto/sha256"
// 	"fmt"
// 	"log"
// 	"math/big"
// 	"testing"

// 	// "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
// )

// // Helper function to convert big.Int to fixed-length byte slice
// func bigIntToBytes(n *big.Int, length int) []byte {
// 	bytes := n.Bytes()
// 	if len(bytes) > length {
// 		return bytes[len(bytes)-length:]
// 	}

// 	result := make([]byte, length)
// 	copy(result[length-len(bytes):], bytes)
// 	return result
// }

// // Helper function to generate a deterministic hash for testing
// func generateTestHash() []byte {
// 	// Create a deterministic hash by hashing some fixed data
// 	hasher := sha256.New()
// 	hasher.Write([]byte("test_dln_proof_hash_seed"))
// 	hash := hasher.Sum(nil)

// 	// We need 16 bytes for 128 bits (128 iterations)
// 	return hash[:16]
// }

// // func TestVerifyDLNProof(t *testing.T) {
// // 	// Load test fixtures
// // 	localPartySaveData, _, err := keygen.LoadKeygenTestFixtures(1)
// // 	if err != nil {
// // 		t.Fatal(err)
// // 	}

// // 	params := localPartySaveData[0].LocalPreParams

// // 	// Convert big.Int parameters to byte slices
// // 	// Assuming 256-byte length for RSA-2048 parameters
// // 	const keyByteLen = 256

// // 	h1Bytes := bigIntToBytes(params.H1i, keyByteLen)
// // 	nBytes := bigIntToBytes(params.NTildei, keyByteLen)

// // 	// For the secret value (x in the proof), we'll use Alpha
// // 	xBytes := bigIntToBytes(params.Alpha, keyByteLen)

// // 	// We need p and q values. Since these might not be directly available,
// // 	// we'll create test values or extract them if available
// // 	var pBytes, qBytes []byte

// // 	// Check if P and Q are available in the params
// // 	if params.P != nil && params.Q != nil {
// // 		pBytes = bigIntToBytes(params.P, keyByteLen/2) // p and q are typically half the size of n
// // 		qBytes = bigIntToBytes(params.Q, keyByteLen/2)
// // 	} else {
// // 		// Generate test prime values if not available
// // 		p, err := rand.Prime(rand.Reader, 1024) // 1024-bit prime
// // 		if err != nil {
// // 			t.Fatal("Failed to generate prime p:", err)
// // 		}
// // 		q, err := rand.Prime(rand.Reader, 1024) // 1024-bit prime
// // 		if err != nil {
// // 			t.Fatal("Failed to generate prime q:", err)
// // 		}

// // 		pBytes = bigIntToBytes(p, keyByteLen/2)
// // 		qBytes = bigIntToBytes(q, keyByteLen/2)

// // 		// Update n to be p*q for consistency
// // 		n := new(big.Int).Mul(p, q)
// // 		nBytes = bigIntToBytes(n, keyByteLen)
// // 	}

// // 	// Generate a test hash
// // 	hash := generateTestHash()

// // 	// Generate the DLN proof
// // 	alphaList, tList, err := DLNProve(
// // 		h1Bytes,    // h1
// // 		xBytes,     // x (secret)
// // 		pBytes,     // p
// // 		qBytes,     // q
// // 		nBytes,     // N
// // 		hash,       // hash
// // 		keyByteLen, // output length
// // 	)
// // 	if err != nil {
// // 		t.Fatal("DLN proof generation failed:", err)
// // 	}
// // 	for tL := range tList {
// // 		fmt.Print(len(tList[tL]))
// // 	}
// // 	// Verify the proof
// // 	// We need to compute h2 = h1^x mod N for verification
// // 	h1 := new(big.Int).SetBytes(h1Bytes)
// // 	x := new(big.Int).SetBytes(xBytes)
// // 	N := new(big.Int).SetBytes(nBytes)
// // 	h2 := new(big.Int).Exp(h1, x, N)
// // 	h2Bytes := bigIntToBytes(h2, keyByteLen)

// // 	ok, err := DLNVerify(
// // 		h1Bytes,   // h1
// // 		h2Bytes,   // h2
// // 		nBytes,    // N
// // 		alphaList, // alpha values
// // 		tList,     // t values
// // 		hash,      // hash
// // 	)
// // 	if err != nil {
// // 		t.Fatal("DLN proof verification failed with error:", err)
// // 	}

// // 	if !ok {
// // 		t.Fatal("DLN proof verification failed")
// // 	}

// // 	log.Println("DLN proof generated and verified successfully")
// // }

// func TestDLNProofWithInvalidData(t *testing.T) {
// 	// Test with invalid parameters to ensure proper error handling

// 	// Test with empty hash
// 	_, _, err := DLNProve(
// 		make([]byte, 256), // h1
// 		make([]byte, 256), // x
// 		make([]byte, 128), // p
// 		make([]byte, 128), // q
// 		make([]byte, 256), // N
// 		[]byte{},          // empty hash - should fail
// 		256,               // output length
// 	)
// 	if err == nil {
// 		t.Fatal("Expected error with empty hash, but got none")
// 	}

// 	// Test with mismatched alpha/t list lengths
// 	hash := generateTestHash()
// 	alphaList := make([][]byte, 64) // Wrong length (should be 128)
// 	tList := make([][]byte, 64)     // Wrong length (should be 128)

// 	for i := range alphaList {
// 		alphaList[i] = make([]byte, 256)
// 		tList[i] = make([]byte, 256)
// 	}

// 	ok, err := DLNVerify(
// 		make([]byte, 256), // h1
// 		make([]byte, 256), // h2
// 		make([]byte, 256), // N
// 		alphaList,         // wrong length
// 		tList,             // wrong length
// 		hash,
// 	)
// 	if err == nil {
// 		t.Fatal("Expected error with wrong list lengths, but got none")
// 	}
// 	if ok {
// 		t.Fatal("Expected verification to fail, but it passed")
// 	}
// }
