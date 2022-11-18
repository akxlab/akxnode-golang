package aknode

import (
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"

	"net"

	"akxsystem/src/p2p"
)

type AkNode struct {
	ID   *p2p.ID
	Conn net.Conn
	IP   net.IP
	dkg  *dkg.DistKeyGenerator
}
