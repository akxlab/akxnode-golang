package p2p

import (
	"github.com/davecgh/go-spew/spew"

	"akxsystem/src/common/types"
	"akxsystem/src/utils"
)

type ID [20]byte

func GenerateNewID() ID {
	b, _ := utils.GetRandomSeed()
	str := utils.EncodeToHex(b)
	addr := types.StringToAddress(str)

	var buf ID
	copy(buf[:], addr.Bytes()[:])
	return buf
}

func (id *ID) String() string {
	addr := id.Address()
	return addr.String()
}

func (id *ID) Bytes() []byte {
	addr := id.Address()
	return addr.Bytes()
}

func (id *ID) Address() types.Address {
	return types.BytesToAddress(id[:])
}

func init() {
	nodeID := GenerateNewID()
	spew.Dump(nodeID)
}
