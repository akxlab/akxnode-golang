package core

import (
	"akxsystem/src/common/types"
)

type Genesis struct {
	//Config    *config.Config // not necessary in genesis
	//Nonce     []byte // always 0
	Timestamp uint64
	// extradata renamed to payload makes more sense
	Payload []byte `json:"payload,omitempty"`

	// no gas limit for genesis as there is no way to charge for it yet
	// GasLimit  uint64                            `json:"gasLimit"`
	// mixhash replaced by a more secure keyed blake3 hash
	KeyedHash []byte    `json:"keyedHash"`
	Coinbase  *Coinbase `json:"coinbase"`
	// Allocations are not needed here will be inside coinbase instead
	//Alloc     map[types.Address]*GenesisAccount `json:"alloc,omitempty"`

	// Override
	StateRoot types.Hash
}

func (g *Genesis) Header() *Header {
	stateRoot := types.EmptyRootHash

	if g.StateRoot != types.ZeroHash {
		stateRoot = g.StateRoot
	}

	header := &Header{
		//Nonce:        g.Nonce,
		Timestamp: g.Timestamp,

		KeyedHash:    g.KeyedHash,
		Coinbase:     g.Coinbase.RootAddress,
		StateRoot:    stateRoot,
		ReceiptsRoot: types.EmptyRootHash,
		TxRoot:       types.EmptyRootHash,
	}
	return header
}
