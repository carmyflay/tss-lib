package dlnproofgmp

import (
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	cmts "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/ncw/gmp"
)

const Iterations = 128

type Proof struct {
	Alpha [Iterations]*gmp.Int
	T     [Iterations]*gmp.Int
}

// GetRandomPositiveGMPInt generates a positive random integer less than upperBound
func GetRandomPositiveGMPInt(rand io.Reader, upperBound *gmp.Int) *gmp.Int {
	if upperBound.Sign() <= 0 {
		panic("upperBound must be > 0")
	}
	nBytes := (upperBound.BitLen() + 7) / 8
	b := make([]byte, nBytes)
	r := new(gmp.Int)

	for {
		_, err := io.ReadFull(rand, b)
		if err != nil {
			panic(fmt.Errorf("GetRandomPositiveGMPInt: %v", err))
		}
		b[0] &= (1 << (uint(upperBound.BitLen()) % 8)) - 1 // clear high bits
		r.SetBytes(b)
		if r.Cmp(upperBound) < 0 && r.Sign() > 0 {
			return r
		}
	}
}

func NewDLNProof(h1, h2, x, p, q, N *gmp.Int, rand io.Reader) *Proof {
	var gPQ gmp.Int
	gPQ.Mul(p, q)

	alpha := [Iterations]*gmp.Int{}
	a := [Iterations]*gmp.Int{}

	for i := 0; i < Iterations; i++ {
		r := GetRandomPositiveGMPInt(rand, &gPQ)
		a[i] = r
		alpha[i] = new(gmp.Int).Exp(h1, r, N)
	}

	msg := make([][]byte, 3+Iterations)
	msg[0], msg[1], msg[2] = h1.Bytes(), h2.Bytes(), N.Bytes()
	for i := 0; i < Iterations; i++ {
		msg[3+i] = alpha[i].Bytes()
	}
	c := common.SHA512_256(msg...)

	t := [Iterations]*gmp.Int{}
	var tGMP, tmp gmp.Int
	for i := 0; i < Iterations; i++ {
		tGMP.Set(a[i])
		if (c[i/8]>>(i%8))&1 == 1 {
			tmp.Set(x)
			tGMP.Add(&tGMP, &tmp)
		}
		tGMP.Mod(&tGMP, &gPQ)
		t[i] = new(gmp.Int).Set(&tGMP)
	}

	return &Proof{Alpha: alpha, T: t}
}

func (p *Proof) VerifyGMP(h1, h2, N *gmp.Int) bool {
	if p == nil || N.Sign() <= 0 {
		return false
	}

	msg := make([][]byte, 3+Iterations)
	msg[0], msg[1], msg[2] = h1.Bytes(), h2.Bytes(), N.Bytes()
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		msg[3+i] = p.Alpha[i].Bytes()
	}
	c := common.SHA512_256(msg...)

	var h1ExpTi, rhs gmp.Int
	for i := 0; i < Iterations; i++ {
		h1ExpTi.Exp(h1, p.T[i], N)
		if (c[i/8]>>(i%8))&1 == 1 {
			rhs.Mul(p.Alpha[i], h2).Mod(&rhs, N)
		} else {
			rhs.Set(p.Alpha[i]).Mod(&rhs, N)
		}
		if h1ExpTi.Cmp(&rhs) != 0 {
			return false
		}
	}
	return true
}

// toBig converts *gmp.Int to *big.Int for serialization
func toBig(x *gmp.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).SetBytes(x.Bytes())
}

// toGMP converts *big.Int to *gmp.Int
func toGMP(x *big.Int) *gmp.Int {
	if x == nil {
		return nil
	}
	return new(gmp.Int).SetBytes(x.Bytes())
}

func (p *Proof) Serialize() ([][]byte, error) {
	cb := cmts.NewBuilder()
	alphaBig := make([]*big.Int, Iterations)
	tBig := make([]*big.Int, Iterations)
	for i := 0; i < Iterations; i++ {
		alphaBig[i] = toBig(p.Alpha[i])
		tBig[i] = toBig(p.T[i])
	}
	cb = cb.AddPart(alphaBig)
	cb = cb.AddPart(tBig)
	ints, err := cb.Secrets()
	if err != nil {
		return nil, err
	}
	bzs := make([][]byte, len(ints))
	for i, part := range ints {
		bzs[i] = part.Bytes()
	}
	return bzs, nil
}

func UnmarshalDLNProof(bzs [][]byte) (*Proof, error) {
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	parsed, err := cmts.ParseSecrets(bis)
	if err != nil {
		return nil, err
	}
	if len(parsed) != 2 {
		return nil, fmt.Errorf("UnmarshalDLNProof expected 2 parts but got %d", len(parsed))
	}
	pf := new(Proof)
	for i := 0; i < Iterations; i++ {
		pf.Alpha[i] = toGMP(parsed[0][i])
		pf.T[i] = toGMP(parsed[1][i])
	}
	return pf, nil
}
