package core

import (
	"akxsystem/src/common/types"
)

type Header struct {
	Timestamp    uint64
	KeyedHash    []byte
	Coinbase     types.Address
	StateRoot    types.Hash
	ReceiptsRoot types.Hash
	TxRoot       types.Hash
}
