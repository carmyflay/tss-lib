// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package dlnproof

import (
	"fmt"
	"io"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	cmts "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/ncw/gmp"
)

const Iterations = 128

type (
	Proof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

// var one = big.NewInt(1)

func NewDLNProof(h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	gH1 := toGMP(h1)
	gX := toGMP(x)
	gP := toGMP(p)
	gQ := toGMP(q)
	gN := toGMP(N)

	var gPQ gmp.Int
	gPQ.Mul(gP, gQ)
	pqBig := new(big.Int).SetBytes(gPQ.Bytes())

	a := make([]*gmp.Int, Iterations)
	alpha := [Iterations]*big.Int{}

	// Reusable vars
	var rBig *big.Int
	var exp gmp.Int

	for i := 0; i < Iterations; i++ {
		rBig = common.GetRandomPositiveInt(rand, pqBig)
		a[i] = toGMP(rBig)
		alpha[i] = toBig(exp.Exp(gH1, a[i], gN))
	}

	// Hash challenge
	msg := make([]*big.Int, 3+Iterations)
	msg[0], msg[1], msg[2] = h1, h2, N
	copy(msg[3:], alpha[:])
	c := common.SHA512_256i(msg...)

	t := [Iterations]*big.Int{}
	var tGMP, tTmp gmp.Int
	for i := 0; i < Iterations; i++ {
		tGMP.Set(a[i])
		if c.Bit(i) == 1 {
			tTmp.Mul(gX, gmp.NewInt(1)) // reuse Mul
			tGMP.Add(&tGMP, &tTmp)
		}
		tGMP.Mod(&tGMP, &gPQ)
		t[i] = toBig(&tGMP)
	}

	return &Proof{Alpha: alpha, T: t}
}

func (p *Proof) Verify(h1, h2, N *big.Int) bool {
	if p == nil || N.Sign() <= 0 {
		return false
	}

	gH1 := toGMP(h1)
	gH2 := toGMP(h2)
	gN := toGMP(N)

	msg := make([]*big.Int, 3+Iterations)
	msg[0], msg[1], msg[2] = h1, h2, N
	copy(msg[3:], p.Alpha[:])
	c := common.SHA512_256i(msg...)

	// Reusable vars
	var tGMP, alphaGMP, h1ExpTi, h2ExpCi, rhs gmp.Int

	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}

		tGMP.Set(toGMP(p.T[i]))
		alphaGMP.Set(toGMP(p.Alpha[i]))

		h1ExpTi.Exp(gH1, &tGMP, gN)

		if c.Bit(i) == 1 {
			h2ExpCi.Set(gH2)
			rhs.Mul(&alphaGMP, &h2ExpCi).Mod(&rhs, gN)
		} else {
			rhs.Set(&alphaGMP).Mod(&rhs, gN)
		}

		if h1ExpTi.Cmp(&rhs) != 0 {
			return false
		}
	}
	return true
}

func (p *Proof) Serialize() ([][]byte, error) {
	cb := cmts.NewBuilder()
	cb = cb.AddPart(p.Alpha[:])
	cb = cb.AddPart(p.T[:])
	ints, err := cb.Secrets()
	if err != nil {
		return nil, err
	}
	bzs := make([][]byte, len(ints))
	for i, part := range ints {
		if part == nil {
			bzs[i] = []byte{}
			continue
		}
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
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d parts but got %d", 2, len(parsed))
	}
	pf := new(Proof)
	if len1 := copy(pf.Alpha[:], parsed[0]); len1 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len1)
	}
	if len2 := copy(pf.T[:], parsed[1]); len2 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len2)
	}
	return pf, nil
}
