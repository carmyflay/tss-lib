package ecdsa

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/implement"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type ECDSAParty struct {
	implement.BaseParty
	preParams     keygen.LocalPreParams
	shareData     *keygen.LocalPartySaveData
	reshareParams *tss.ReSharingParameters
	curve         elliptic.Curve
}

func NewECDSAParty(partyID string) *ECDSAParty {
	return &ECDSAParty{
		BaseParty: *implement.NewBaseParty(partyID),
		curve:     tss.S256(),
	}
}

func (p *ECDSAParty) Init(participants []string, threshold int, preParams keygen.LocalPreParams, sender implement.Sender) {
	p.preParams = preParams
	sortedPartyIDs := implement.CreateSortedPartyIDs(participants)
	// Update the partyID index
	p.PartyID.Index = implement.GetLocalPartyIndex(sortedPartyIDs, p.PartyID.Id)
	ctx := tss.NewPeerContext(sortedPartyIDs)
	p.Params = tss.NewParameters(p.curve, ctx, p.PartyID, len(participants), threshold)
	p.SetSender(sender)
	go p.SendMessages()
}

func (p *ECDSAParty) InitReshare(oldParticipants []string, newParticipants []string, oldThreshold int, newThreshold int, preParams keygen.LocalPreParams, sender implement.Sender) {
	p.preParams = preParams
	oldSortedPartyIDs := implement.CreateSortedPartyIDs(oldParticipants)
	newSortedPartyIDs := implement.CreateSortedPartyIDs(newParticipants)

	// Only update index for new parties
	if p.PartyID.Index == -1 {
		p.PartyID.Index = implement.GetLocalPartyIndex(newSortedPartyIDs, p.PartyID.Id)
	}

	p.reshareParams = tss.NewReSharingParameters(
		p.curve,
		tss.NewPeerContext(oldSortedPartyIDs),
		tss.NewPeerContext(newSortedPartyIDs),
		p.PartyID,
		len(oldParticipants),
		oldThreshold,
		len(newParticipants),
		newThreshold,
	)
	p.SetSender(sender)
	go p.SendMessages()
}

func (p *ECDSAParty) Keygen(done func(*keygen.LocalPartySaveData)) {
	log.Printf("Party %s starting keygen\n", p.PartyID.Id)
	defer log.Printf("Party %s ending keygen\n", p.PartyID.Id)

	endCh := make(chan *keygen.LocalPartySaveData, 1)
	localParty := keygen.NewLocalParty(p.Params, p.Out, endCh, p.preParams)

	go func() {
		if err := localParty.Start(); err != nil {
			p.ErrChan <- err
		}
	}()

	for {
		select {
		case share := <-endCh:
			if done != nil {
				done(share)
			}
			return
		case msg := <-p.In:
			p.processMsg(localParty, msg)
		}
	}
}

func (p *ECDSAParty) Sign(msg []byte, done func(*common.SignatureData)) {
	log.Printf("Party %s starting sign\n", p.PartyID.Id)
	defer log.Printf("Party %s ending sign\n", p.PartyID.Id)

	if p.shareData == nil {
		log.Printf("Party %s has no share data", p.PartyID.Id)
		return
	}

	endCh := make(chan *common.SignatureData, 1)
	msgToSign := hashToInt(msg, p.curve)
	localParty := signing.NewLocalParty(msgToSign, p.Params, *p.shareData, p.Out, endCh)

	go func() {
		if err := localParty.Start(); err != nil {
			log.Printf("Party %s failed to start: %v\n", p.PartyID.Id, err)
			panic(err)
		}
	}()

	for {
		select {
		case sig := <-endCh:
			if done != nil {
				done(sig)
			}
			return
		case msg := <-p.In:
			p.processMsg(localParty, msg)
		}
	}
}

func (p *ECDSAParty) Reshare(done func(*keygen.LocalPartySaveData)) {
	log.Printf("Party %s starting reshare\n", p.PartyID.Id)
	defer log.Printf("Party %s ending reshare\n", p.PartyID.Id)

	// Initialize share data for new participants
	if p.shareData == nil {
		data := keygen.NewLocalPartySaveData(p.reshareParams.NewPartyCount())
		data.LocalPreParams = p.preParams
		p.shareData = &data
	}

	endCh := make(chan *keygen.LocalPartySaveData, 1)
	localParty := resharing.NewLocalParty(p.reshareParams, *p.shareData, p.Out, endCh)

	go func() {
		if err := localParty.Start(); err != nil {
			p.ErrChan <- err
		}
	}()

	for {
		select {
		case share := <-endCh:
			if done != nil {
				done(share)
			}
			return
		case msg := <-p.In:
			if err := p.processMsg(localParty, msg); err != nil {
				p.ErrChan <- err
			}
		}
	}
}

func (p *ECDSAParty) processMsg(localParty tss.Party, msg tss.Message) error {
	bz, _, err := msg.WireBytes()
	if err != nil {
		return err
	}
	ok, err := localParty.UpdateFromBytes(bz, msg.GetFrom(), msg.IsBroadcast())
	if !ok {
		return err
	}
	return nil
}

func (p *ECDSAParty) SetShareData(shareData []byte) {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(shareData, &localSaveData)
	if err != nil {
		p.ErrChan <- fmt.Errorf("failed deserializing shares: %w", err)
	}

	// Validate share data
	if localSaveData.ECDSAPub == nil {
		p.ErrChan <- fmt.Errorf("share data has nil public key")
	}
	if localSaveData.Xi == nil {
		p.ErrChan <- fmt.Errorf("share data has nil private share")
	}

	// Set curve for all points
	localSaveData.ECDSAPub.SetCurve(p.curve)
	for _, xj := range localSaveData.BigXj {
		if xj == nil {
			p.ErrChan <- fmt.Errorf("share data has nil public share")
		}
		xj.SetCurve(p.curve)
	}

	p.shareData = &localSaveData
}

// hashToInt is taken as-is from the Go ECDSA standard library
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
