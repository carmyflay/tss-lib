package dlnproofc

import (
	"crypto/rand"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

func TestVerifyDLNProofZ(t *testing.T) {
	// Load test fixtures
	localPartySaveData, _, err := keygen.LoadKeygenTestFixtures(1)
	if err != nil {
		t.Fatal(err)
	}

	params := localPartySaveData[0].LocalPreParams

	proof := NewDLNProof(
		params.H1i,
		params.H2i,
		params.Alpha,
		params.P,
		params.Q,
		params.NTildei,
		rand.Reader,
	)

	ok := proof.Verify(params.H1i, params.H2i, params.NTildei)
	if !ok {
		t.Fatal("DLN proof verification failed")
	}

}
