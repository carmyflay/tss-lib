package implement

import (
	"log"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	defaultChanSize = 1000
)

type Sender func(msg tss.Message)

type BaseParty struct {
	PartyID   *tss.PartyID
	Params    *tss.Parameters
	In        chan tss.Message
	Out       chan tss.Message
	ErrChan   chan error
	closeChan chan struct{}
	sender    Sender
}

func NewBaseParty(partyID string) *BaseParty {
	return &BaseParty{
		PartyID:   tss.NewPartyID(partyID, partyID, new(big.Int).SetBytes([]byte(partyID))),
		In:        make(chan tss.Message, defaultChanSize),
		Out:       make(chan tss.Message, defaultChanSize),
		ErrChan:   make(chan error, defaultChanSize),
		closeChan: make(chan struct{}),
	}
}

func (p *BaseParty) SetSender(sender Sender) {
	p.sender = sender
}

func CreateSortedPartyIDs(participants []string) tss.SortedPartyIDs {
	partyIDs := make(tss.UnSortedPartyIDs, len(participants))
	for i, participant := range participants {
		partyIDs[i] = tss.NewPartyID(participant, participant, new(big.Int).SetBytes([]byte(participant)))
	}
	return tss.SortPartyIDs(partyIDs)
}

func GetLocalPartyIndex(partyIDs tss.SortedPartyIDs, partyID string) int {
	for i, pid := range partyIDs {
		if pid.Id == partyID {
			return i
		}
	}
	return -1
}

func (p *BaseParty) OnMsg(msg tss.Message) {
	select {
	case p.In <- msg:
	case <-p.closeChan:
	}
}

func (p *BaseParty) SendMessages() {
	for {
		select {
		case <-p.closeChan:
			return
		case msg := <-p.Out:
			if p.sender != nil {
				p.sender(msg)
			}
		}
	}
}

func (p *BaseParty) NotifyError() {
	for err := range p.ErrChan {
		log.Printf("Party %s received error: %v", p.PartyID.Id, err)
	}
}

func (p *BaseParty) Close() {
	close(p.closeChan)
	close(p.In)
	close(p.Out)
	close(p.ErrChan)
}
