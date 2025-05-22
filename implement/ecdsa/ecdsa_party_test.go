package ecdsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/implement"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/stretchr/testify/assert"
)

func TestECDSAParty(t *testing.T) {
	party1 := NewECDSAParty("party1")
	party2 := NewECDSAParty("party2")
	party3 := NewECDSAParty("party3")

	preParams1, _ := loadPreparams("party1")
	preParams2, _ := loadPreparams("party2")
	preParams3, _ := loadPreparams("party3")

	assert.NotNil(t, preParams1)
	assert.NotNil(t, preParams2)
	assert.NotNil(t, preParams3)

	senders := senders([]*ECDSAParty{party1, party2, party3})

	party1.Init([]string{"party1", "party2", "party3"}, 2, *preParams1, senders[0])
	party2.Init([]string{"party1", "party2", "party3"}, 2, *preParams2, senders[1])
	party3.Init([]string{"party1", "party2", "party3"}, 2, *preParams3, senders[2])

	go party1.NotifyError()
	go party2.NotifyError()
	go party3.NotifyError()

	shares := keygenAll([]*ECDSAParty{party1, party2, party3})
	assert.Equal(t, 3, len(shares))
	t.Logf("Done keygen")

	// Set share data for each party using their own share
	party1.SetShareData(shares["party1"])
	party2.SetShareData(shares["party2"])
	party3.SetShareData(shares["party3"])

	sigs := signAll([]*ECDSAParty{party1, party2, party3}, []byte("test"))
	assert.Equal(t, 3, len(sigs))
	t.Logf("Done sign")

	// Close all parties
	// party1.Close()
	// party2.Close()
	// party3.Close()

	// Reshare
	party1Reshare := NewECDSAParty("party1-reshare")
	party2Reshare := NewECDSAParty("party2-reshare")

	reshareSenders := senderForReshare([]*ECDSAParty{party1, party2, party3, party1Reshare, party2Reshare})

	party1Reshare.InitReshare([]string{"party1", "party2", "party3"}, []string{"party1-reshare", "party2-reshare"}, 2, 1, *preParams1, reshareSenders[3])
	party2Reshare.InitReshare([]string{"party1", "party2", "party3"}, []string{"party1-reshare", "party2-reshare"}, 2, 1, *preParams2, reshareSenders[4])

	// Init reshare for old parties too
	party1.InitReshare([]string{"party1", "party2", "party3"}, []string{"party1-reshare", "party2-reshare"}, 2, 1, *preParams1, reshareSenders[0])
	party2.InitReshare([]string{"party1", "party2", "party3"}, []string{"party1-reshare", "party2-reshare"}, 2, 1, *preParams2, reshareSenders[1])
	party3.InitReshare([]string{"party1", "party2", "party3"}, []string{"party1-reshare", "party2-reshare"}, 2, 1, *preParams3, reshareSenders[2])

	go party1Reshare.NotifyError()
	go party2Reshare.NotifyError()

	reshareShares := reshareAll([]*ECDSAParty{party1, party2, party3, party1Reshare, party2Reshare})
	assert.Equal(t, 5, len(reshareShares))
	t.Logf("Done reshare")

	// Close reshare parties
	// party1Reshare.Close()
	// party2Reshare.Close()
}

func keygenAll(parties []*ECDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex // Protect map access

	for _, party := range parties {
		go func(p *ECDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Party %s panicked: %v\n", p.PartyID.Id, r)
				}
			}()
			p.Keygen(func(share *keygen.LocalPartySaveData) {
				bz, err := json.Marshal(share)
				if err != nil {
					log.Printf("Party %s failed to marshal share data: %v\n", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				shares[p.PartyID.Id] = bz
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return shares
}

func signAll(parties []*ECDSAParty, msg []byte) [][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	var sigs [][]byte
	for _, party := range parties {
		go func(p *ECDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Party %s panicked: %v\n", p.PartyID.Id, r)
				}
			}()
			p.Sign(msg, func(sig *common.SignatureData) {
				bz, err := json.Marshal(sig)
				if err != nil {
					log.Printf("Party %s failed to marshal signature: %v\n", p.PartyID.Id, err)
					return
				}
				sigs = append(sigs, bz)
			})
		}(party)
	}
	wg.Wait()
	return sigs
}

func reshareAll(parties []*ECDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex // Protect map access

	for _, party := range parties {
		go func(p *ECDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Party %s panicked: %v\n", p.PartyID.Id, r)
				}
			}()
			p.Reshare(func(share *keygen.LocalPartySaveData) {
				bz, err := json.Marshal(share)
				if err != nil {
					log.Printf("Party %s failed to marshal share data: %v\n", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				shares[p.PartyID.Id] = bz
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return shares
}

func senders(parties []*ECDSAParty) []implement.Sender {
	var senders []implement.Sender
	for _, src := range parties {
		src := src
		sender := func(msg tss.Message) {
			var toLog string
			if msg.IsBroadcast() {
				toLog = "broadcast"
			} else {
				toLog = msg.GetTo()[0].Id
			}
			log.Printf("Party %s sending message to %v\n",
				src.PartyID.Id, toLog)
			if msg.IsBroadcast() {
				for _, dst := range parties {
					if dst.PartyID.Id == src.PartyID.Id {
						continue
					}
					dst.OnMsg(msg)
				}
			} else {
				to := msg.GetTo()
				if to == nil {
					log.Printf("Warning: Party %s message has nil recipients\n", src.PartyID.Id)
					return
				}
				for _, recipient := range to {
					for _, dst := range parties {
						if recipient.Id == dst.PartyID.Id {
							dst.OnMsg(msg)
							break
						}
					}
				}
			}
		}
		senders = append(senders, sender)
	}
	return senders
}

func senderForReshare(parties []*ECDSAParty) []implement.Sender {
	var senders []implement.Sender
	for _, src := range parties {
		src := src
		sender := func(msg tss.Message) {
			to := msg.GetTo()
			log.Printf("Party %s sending message to %v\n",
				src.PartyID.Id, to)
			if to == nil {
				log.Printf("Warning: Party %s message has nil recipients\n", src.PartyID.Id)
				return
			}
			for _, recipient := range to {
				for _, dst := range parties {
					if recipient.Id == dst.PartyID.Id {
						log.Printf("Party %s sending message to %s\n", src.PartyID.Id, dst.PartyID.Id)
						dst.OnMsg(msg)
						break
					}
				}
			}
		}
		senders = append(senders, sender)
	}
	return senders
}

func loadPreparams(partyID string) (*keygen.LocalPreParams, error) {
	// Try to read existing file
	data, err := os.ReadFile("preparams_" + partyID + ".json")
	if err == nil {
		// File exists, try to unmarshal
		var params *keygen.LocalPreParams
		if err := json.Unmarshal(data, &params); err == nil {
			return params, nil
		}
		// If unmarshal fails, we'll generate new params
	}

	// Generate new parameters
	params, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		return nil, err
	}

	// Save the new parameters
	if data, err := json.Marshal(params); err == nil {
		os.WriteFile("preparams_"+partyID+".json", data, 0644)
	}

	return params, nil
}

func ThresholdPK(shareData *keygen.LocalPartySaveData) ([]byte, error) {
	if shareData == nil {
		return nil, fmt.Errorf("must call SetShareData() before attempting to sign")
	}

	pk := shareData.ECDSAPub

	ecdsaPK := &ecdsa.PublicKey{
		Curve: shareData.ECDSAPub.Curve(),
		X:     pk.X(),
		Y:     pk.Y(),
	}

	return encodeS256PubKey(ecdsaPK)
}

func encodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return publicKeyBytes, nil
}
