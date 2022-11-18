package core

import (
	"math/big"

	"akxsystem/src/common/types"
)

type Coinbase struct {
	RootAddress types.Address
	Code        map[string][]byte
	Balance     *big.Int
	Nonce       uint64
	PrivateKey  []byte
	BaseCoin    *Currency
	Alloc       map[string]*big.Int
}

type Currency struct {
	Name            string
	Symbol          string
	ContractAddress types.Address
	Minted          *big.Int
	Burned          *big.Int
	LastSerial      string
	Owner           types.Address
}
