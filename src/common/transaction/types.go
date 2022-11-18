package transaction

import (
	"akxsystem/src/common/types"
	"math/big"
	"sync/atomic"
)

type Transaction struct {
	Nonce   uint64
	To      *types.Address
	From    types.Address
	Value   *big.Int
	Hash    []byte
	Input   []byte
	Extra   []byte
	Note    []byte
	GasData *Gas
	size    atomic.Value
	vrs     VRS
}

type VRS struct {
	V *big.Int
	R *big.Int
	S *big.Int
}

type Gas struct {
	Max         *big.Int
	Min         *big.Int
	Price       *big.Int
	Consumption *big.Int
	Cost        *big.Int
}

type SignedTransaction struct {
	Tx         *Transaction
	Signatures map[string][]byte
}
