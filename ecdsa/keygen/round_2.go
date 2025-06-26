// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/crypto/facproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/modproof"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	paillierBitsLen = 2048
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	common.Logger.Debugf(
		"%s Setting up DLN verification with concurrency level of %d",
		round.PartyID(),
		round.Concurrency(),
	)
	dlnVerifier := NewDlnProofVerifier(round.Concurrency())
	i := round.PartyID().Index

	h1H2Map := make(map[[32]byte]struct{}, len(round.temp.kgRound1Messages)*2)
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))

	wg := new(sync.WaitGroup)

	for j, msg := range round.temp.kgRound1Messages {
		r1msg := msg.Content().(*KGRound1Message)
		H1j := r1msg.UnmarshalH1()
		H2j := r1msg.UnmarshalH2()
		NTildej := r1msg.UnmarshalNTilde()
		paillierPKj := r1msg.UnmarshalPaillierPK()

		if paillierPKj.N.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("paillier modulus too small"), msg.GetFrom())
		}
		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j == h2j"), msg.GetFrom())
		}
		if NTildej.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("NTildej too small"), msg.GetFrom())
		}

		h1Sum := sha256.Sum256(H1j.Bytes())
		h2Sum := sha256.Sum256(H2j.Bytes())

		if _, ok := h1H2Map[h1Sum]; ok {
			return round.WrapError(errors.New("h1j reused"), msg.GetFrom())
		}
		if _, ok := h1H2Map[h2Sum]; ok {
			return round.WrapError(errors.New("h2j reused"), msg.GetFrom())
		}
		h1H2Map[h1Sum] = struct{}{}
		h1H2Map[h2Sum] = struct{}{}

		wg.Add(2)
		_j := j
		_msg := msg

		dlnVerifier.VerifyDLNProof1(r1msg, H1j, H2j, NTildej, func(ok bool) {
			if !ok {
				dlnProof1FailCulprits[_j] = _msg.GetFrom()
			}
			wg.Done()
		})
		dlnVerifier.VerifyDLNProof2(r1msg, H2j, H1j, NTildej, func(ok bool) {
			if !ok {
				dlnProof2FailCulprits[_j] = _msg.GetFrom()
			}
			wg.Done()
		})
	}
	wg.Wait()

	for _, culprit := range append(dlnProof1FailCulprits, dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof failed"), culprit)
		}
	}

	for j, msg := range round.temp.kgRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*KGRound1Message)
		round.save.PaillierPKs[j] = r1msg.UnmarshalPaillierPK()
		round.save.NTildej[j] = r1msg.UnmarshalNTilde()
		round.save.H1j[j] = r1msg.UnmarshalH1()
		round.save.H2j[j] = r1msg.UnmarshalH2()
		round.temp.KGCs[j] = r1msg.UnmarshalCommitment()
	}

	shares := round.temp.shares
	ContextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	var msg1Wg sync.WaitGroup
	for j, Pj := range round.Parties().IDs() {
		msg1Wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer msg1Wg.Done()

			var facProof *facproof.ProofFac
			if round.Params().NoProofFac() {
				facProof = &facproof.ProofFac{}
			} else {
				facProof, _ = facproof.NewProof(
					ContextI,
					round.EC(),
					round.save.PaillierSK.N,
					round.save.NTildej[j],
					round.save.H1j[j],
					round.save.H2j[j],
					round.save.PaillierSK.P,
					round.save.PaillierSK.Q,
					round.Rand(),
				)
			}
			r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), shares[j], facProof)
			if j == i {
				round.temp.kgRound2Message1s[j] = r2msg1
			} else {
				round.out <- r2msg1
			}
		}(j, Pj)
	}

	// MOD proof chạy song song
	var modProof *modproof.ProofMod
	var modErr error
	modDone := make(chan struct{})
	go func() {
		if round.Parameters.NoProofMod() {
			modProof = &modproof.ProofMod{}
		} else {
			modProof, modErr = modproof.NewProof(
				ContextI,
				round.save.PaillierSK.N,
				round.save.PaillierSK.P,
				round.save.PaillierSK.Q,
				round.Rand(),
			)
		}
		close(modDone)
	}()

	msg1Wg.Wait()
	<-modDone
	if modErr != nil {
		return round.WrapError(modErr, round.PartyID())
	}

	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.deCommitPolyG, modProof)
	round.temp.kgRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	ret := true
	for j, msg := range round.temp.kgRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		msg2 := round.temp.kgRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
